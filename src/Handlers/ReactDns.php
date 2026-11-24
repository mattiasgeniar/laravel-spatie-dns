<?php

namespace Spatie\Dns\Handlers;

use Composer\InstalledVersions;
use React\Dns\Config\Config;
use React\Dns\Model\Message;
use React\Dns\Model\Record as ResourceRecord;
use React\Dns\Query\Query;
use React\Dns\Query\RetryExecutor;
use React\Dns\Query\SelectiveTransportExecutor;
use React\Dns\Query\TcpTransportExecutor;
use React\Dns\Query\TimeoutException;
use React\Dns\Query\TimeoutExecutor;
use React\Dns\Query\UdpTransportExecutor;
use React\EventLoop\LoopInterface;
use React\EventLoop\StreamSelectLoop;
use React\Promise\PromiseInterface;
use Spatie\Dns\Exceptions\CouldNotFetchDns;
use Spatie\Dns\Records\Record;
use Throwable;

/**
 * Queries the nameserver from inside PHP with react/dns, so no dig process is started.
 * Each answer is written out as the line dig would print and parsed the same way, so the
 * records are equal to the ones the Dig handler returns.
 */
class ReactDns extends Handler
{
    protected ?int $timeout = 2;

    protected ?int $retries = 2;

    /** @var array<string, int> */
    protected array $typeCodes = [
        'A' => 1,
        'NS' => 2,
        'CNAME' => 5,
        'SOA' => 6,
        'PTR' => 12,
        'MX' => 15,
        'TXT' => 16,
        'AAAA' => 28,
        'SRV' => 33,
        'DS' => 43,
        'DNSKEY' => 48,
        'CAA' => 257,
    ];

    /**
     * The names dig prints for each response code. Codes 11 to 15 have no name, and dig
     * prints them as RESERVED11 to RESERVED15.
     *
     * @var array<int, string>
     */
    protected array $responseStatuses = [
        0 => 'NOERROR',
        1 => 'FORMERR',
        2 => 'SERVFAIL',
        3 => 'NXDOMAIN',
        4 => 'NOTIMP',
        5 => 'REFUSED',
        6 => 'YXDOMAIN',
        7 => 'YXRRSET',
        8 => 'NXRRSET',
        9 => 'NOTAUTH',
        10 => 'NOTZONE',
    ];

    /**
     * Response statuses that are real answers. NXDOMAIN means the name does not exist, so
     * returning no records is correct.
     *
     * @var array<int, string>
     */
    protected array $successfulResponseStatuses = ['NOERROR', 'NXDOMAIN'];

    /**
     * Holds the IP addresses of each nameserver hostname this handler has used, so a
     * hostname is only looked up once.
     *
     * @var array<string, array<int, string>>
     */
    protected array $resolvedNameservers = [];

    public function __invoke(string $domain, int $flag, string $type): array
    {
        $lookup = $this->prepareLookup($domain, $type);

        $response = $this->query($lookup['query'], $lookup['nameservers'], $lookup['description']);

        return $this->toRecords($response, $lookup['type'], $lookup['description']);
    }

    /**
     * Sends the query for every type at once and waits for all answers in one run of the
     * event loop. The time this takes is about that of the slowest query, not their sum.
     *
     * The records and exceptions are the same as when each type is fetched on its own. When
     * several types fail, the exception is the one of the first failing type in `$types`.
     */
    public function getRecordsForTypes(string $domain, array $types): array
    {
        $lookups = [];

        $preparationError = null;

        // Fetching each type on its own stops at the type that cannot be prepared, so later
        // types are not prepared here either. The types before it are still queried, because
        // one of them may fail first.
        foreach ($types as $type) {
            try {
                $lookups[] = $this->prepareLookup($domain, $type);
            } catch (Throwable $error) {
                $preparationError = $error;

                break;
            }
        }

        $outcomes = $this->queryConcurrently($lookups);

        $records = [];

        foreach ($lookups as $index => $lookup) {
            $outcome = $outcomes[$index];

            if ($outcome instanceof Throwable) {
                throw CouldNotFetchDns::queryFailed($lookup['description'], $this->failureReason($outcome), $outcome);
            }

            $records = array_merge($records, $this->toRecords($outcome, $lookup['type'], $lookup['description']));
        }

        if ($preparationError !== null) {
            throw $preparationError;
        }

        return $records;
    }

    /**
     * Requires the react/dns version this handler is tested with. An application can have an
     * older one locked, because require-dev does not apply there. Versions before 1.5 can run
     * out of memory on a malformed reply.
     */
    public function canHandle(): bool
    {
        if (! InstalledVersions::isInstalled('react/dns')) {
            return false;
        }

        return version_compare((string) InstalledVersions::getVersion('react/dns'), '1.14.0', '>=');
    }

    /**
     * Asks each nameserver in turn until one answers, the way dig tries each system
     * nameserver. An error status is an answer too, so like dig it does not move on then.
     *
     * @param  array<int, string>  $nameservers
     */
    protected function query(Query $query, array $nameservers, string $description): Message
    {
        // Like dig, a number of tries below 1 counts as 1. dig spends the extra tries on the
        // first nameserver and asks every other nameserver once.
        $tries = max(1, (int) $this->retries);

        foreach ($nameservers as $nameserver) {
            $result = $this->queryNameserver($query, $nameserver, $tries);

            if ($result instanceof Message) {
                return $result;
            }

            $tries = 1;
        }

        throw CouldNotFetchDns::queryFailed($description, $this->failureReason($result), $result);
    }

    /**
     * Runs a private event loop until the query has an answer or has failed. A private loop
     * cannot start or stop timers that the application put on the global loop.
     *
     * The loop is not stopped when the answer arrives. It runs until it is empty, so react/dns
     * can still close the TCP connection it opens for an answer that was too large for UDP.
     */
    protected function queryNameserver(Query $query, string $nameserver, int $tries): Message|Throwable
    {
        $loop = new StreamSelectLoop;

        $result = null;

        $settle = function (Message|Throwable $outcome) use (&$result): void {
            $result = $outcome;
        };

        $this->sendQuery($query, $nameserver, $tries, $loop)->then($settle, $settle);

        $loop->run();

        return $result;
    }

    /**
     * Starts every query on one private event loop and runs the loop until all of them have
     * an answer or have failed. Returns the answer or the error of each lookup, under the same index.
     *
     * @param  array<int, array{type: string, query: Query, nameservers: array<int, string>, description: string}>  $lookups
     * @return array<int, Message|Throwable>
     */
    protected function queryConcurrently(array $lookups): array
    {
        $loop = new StreamSelectLoop;

        $outcomes = [];

        foreach ($lookups as $index => $lookup) {
            $settle = function (Message|Throwable $outcome) use (&$outcomes, $index): void {
                $outcomes[$index] = $outcome;
            };

            $this->queryInTurn($lookup['query'], $lookup['nameservers'], max(1, (int) $this->retries), $loop)
                ->then($settle, $settle);
        }

        $loop->run();

        return $outcomes;
    }

    /**
     * Asks each nameserver in turn until one answers, like query() does, but without running
     * the loop. The first nameserver gets all tries and every other nameserver gets one.
     *
     * @param  array<int, string>  $nameservers
     * @return PromiseInterface<Message>
     */
    protected function queryInTurn(Query $query, array $nameservers, int $tries, LoopInterface $loop): PromiseInterface
    {
        $nameserver = array_shift($nameservers);

        return $this->sendQuery($query, $nameserver, $tries, $loop)->then(
            null,
            function (Throwable $error) use ($query, $nameservers, $loop): PromiseInterface {
                if ($nameservers === []) {
                    throw $error;
                }

                return $this->queryInTurn($query, $nameservers, 1, $loop);
            },
        );
    }

    /**
     * Sends the query to one nameserver on the given loop. The promise settles once the
     * nameserver has answered or every try has failed.
     *
     * @return PromiseInterface<Message>
     */
    protected function sendQuery(Query $query, string $nameserver, int $tries, LoopInterface $loop): PromiseInterface
    {
        // Like dig, a timeout below 1 counts as 1. The tries include the first attempt, and
        // RetryExecutor only counts the attempts after it.
        $executor = new RetryExecutor(
            new TimeoutExecutor(
                new SelectiveTransportExecutor(
                    new UdpTransportExecutor($nameserver, $loop),
                    new TcpTransportExecutor($nameserver, $loop),
                ),
                max(1, (int) $this->timeout),
                $loop,
            ),
            $tries - 1,
        );

        return $executor->query($query);
    }

    /**
     * Checks the type and works out the query, the nameservers to ask and the description
     * that goes into an exception. Throws where fetching this type would throw before any
     * query is sent.
     *
     * @return array{type: string, query: Query, nameservers: array<int, string>, description: string}
     */
    protected function prepareLookup(string $domain, string $type): array
    {
        $type = mb_strtoupper($type);

        if (! isset($this->typeCodes[$type])) {
            throw UnsupportedRecordType::make($type);
        }

        $nameservers = $this->nameserverAddresses();

        $description = "{$domain} {$type} @".implode(',', $nameservers);

        // react/dns adds the root dot itself, so a name that already ends in one would end twice.
        $domain = $this->toAscii(rtrim($domain, '.'), $description);

        return [
            'type' => $type,
            'query' => new Query($domain, $this->typeCodes[$type], Message::CLASS_IN),
            'nameservers' => $nameservers,
            'description' => $description,
        ];
    }

    /**
     * @return Record[]
     */
    protected function toRecords(Message $response, string $type, string $description): array
    {
        $this->guardAgainstErrorResponse($response, $description);

        return $this->transform($type, $this->toLines($response, $type));
    }

    /**
     * Converts a Unicode domain name to its punycode form, the way dig does before it sends
     * the query. react/dns would send the UTF-8 bytes as they are.
     */
    protected function toAscii(string $domain, string $description): string
    {
        if (mb_check_encoding($domain, 'ASCII')) {
            return $domain;
        }

        if (! function_exists('idn_to_ascii')) {
            throw CouldNotFetchDns::queryFailed($description, 'a Unicode domain name needs the intl extension');
        }

        $ascii = idn_to_ascii($domain, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);

        if ($ascii === false) {
            throw CouldNotFetchDns::queryFailed($description, 'the domain name cannot be converted to punycode');
        }

        return $ascii;
    }

    /**
     * The retry executor wraps the last timeout in an exception of its own, whose message
     * repeats the query. The timeout is the actual reason.
     */
    protected function failureReason(Throwable $error): string
    {
        if ($error->getPrevious() instanceof TimeoutException) {
            return 'no reply from the nameserver';
        }

        return $error->getMessage();
    }

    /**
     * Returns the IP addresses to send the query to, in order. dig accepts a hostname, but
     * react/dns needs an IP address.
     *
     * @return array<int, string>
     */
    protected function nameserverAddresses(): array
    {
        $nameserver = (string) $this->nameserver;

        if ($nameserver === '') {
            return $this->systemNameservers();
        }

        return $this->resolvedNameservers[$nameserver] ??= $this->resolveNameserver($nameserver);
    }

    /**
     * Reads the system nameservers on every lookup, like dig, so a change to them is used
     * straight away.
     *
     * @return array<int, string>
     */
    protected function systemNameservers(): array
    {
        $nameservers = Config::loadSystemConfigBlocking()->nameservers;

        if ($nameservers !== []) {
            return $nameservers;
        }

        // react/dns finds the Windows nameservers with wmic, which newer Windows versions no
        // longer include. Elsewhere the list is empty when resolv.conf names no nameserver,
        // and dig then sends the query to the local host.
        if (PHP_OS_FAMILY === 'Windows') {
            throw CouldNotFetchDns::noSystemNameserver();
        }

        return ['127.0.0.1'];
    }

    /**
     * Returns every IPv4 address of a hostname, so the next one is asked when the first
     * does not reply, like dig does.
     *
     * @return array<int, string>
     */
    protected function resolveNameserver(string $nameserver): array
    {
        if (filter_var($nameserver, FILTER_VALIDATE_IP) !== false) {
            return [$nameserver];
        }

        return gethostbynamel($nameserver) ?: throw CouldNotFetchDns::nameserverNotFound($nameserver);
    }

    protected function guardAgainstErrorResponse(Message $response, string $description): void
    {
        if (! $this->throwOnErrorResponse) {
            return;
        }

        $responseStatus = $this->responseStatuses[$response->rcode] ?? "RESERVED{$response->rcode}";

        if (in_array($responseStatus, $this->successfulResponseStatuses, true)) {
            return;
        }

        throw CouldNotFetchDns::nameserverReturnedErrorResponse($responseStatus, $description);
    }

    /**
     * Writes each record of the requested type as the line dig prints for it. The Dig
     * handler reads both the answer and the authority section, so this does too.
     *
     * @return array<int, string>
     */
    protected function toLines(Message $response, string $type): array
    {
        $lines = [];

        foreach ([...$response->answers, ...$response->authority] as $record) {
            if ($record->type !== $this->typeCodes[$type]) {
                continue;
            }

            $data = $this->formatData($record, $type);

            if ($data === null) {
                continue;
            }

            $lines[] = "{$this->formatName($record->name)}\t{$record->ttl}\tIN\t{$type}\t{$data}";
        }

        return $lines;
    }

    protected function formatData(ResourceRecord $record, string $type): ?string
    {
        $data = $record->data;

        return match ($type) {
            'A', 'AAAA' => $data,
            'CNAME', 'NS', 'PTR' => $this->formatName($data),
            'MX' => "{$data['priority']} {$this->formatName($data['target'])}",
            'SRV' => "{$data['priority']} {$data['weight']} {$data['port']} {$this->formatName($data['target'])}",
            'SOA' => implode(' ', [
                $this->formatName($data['mname']),
                $this->formatName($data['rname']),
                $data['serial'],
                $data['refresh'],
                $data['retry'],
                $data['expire'],
                $data['minimum'],
            ]),
            'TXT' => implode(' ', array_map($this->formatCharacterString(...), $data)),
            'CAA' => "{$data['flag']} {$data['tag']} {$this->formatCharacterString($data['value'])}",
            'DS' => $this->formatDs($data),
            'DNSKEY' => $this->formatDnskey($data),
        };
    }

    /**
     * react/dns leaves the trailing dot of the root label off, dig prints it.
     */
    protected function formatName(string $name): string
    {
        return rtrim($name, '.').'.';
    }

    /**
     * Quotes the string the way dig does. A quote or a backslash gets a backslash in front,
     * and a byte that is not printable ASCII is written as a backslash and three digits.
     */
    protected function formatCharacterString(string $value): string
    {
        $escaped = preg_replace_callback(
            '/[^\x20-\x7E]/',
            fn (array $match): string => sprintf('\\%03d', ord($match[0])),
            addcslashes($value, '"\\'),
        );

        return "\"{$escaped}\"";
    }

    /**
     * react/dns does not decode DS records and returns the raw bytes. They hold a 2 byte key
     * tag, a 1 byte algorithm, a 1 byte digest type and the digest.
     */
    protected function formatDs(string $data): ?string
    {
        if (strlen($data) < 5) {
            return null;
        }

        $fields = unpack('nkeytag/Calgorithm/Cdigesttype', $data);

        $digest = strtoupper(bin2hex(substr($data, 4)));

        return "{$fields['keytag']} {$fields['algorithm']} {$fields['digesttype']} {$digest}";
    }

    /**
     * react/dns does not decode DNSKEY records and returns the raw bytes. They hold 2 bytes
     * of flags, a 1 byte protocol, a 1 byte algorithm and the public key.
     */
    protected function formatDnskey(string $data): ?string
    {
        if (strlen($data) < 5) {
            return null;
        }

        $fields = unpack('nflags/Cprotocol/Calgorithm', $data);

        $publicKey = base64_encode(substr($data, 4));

        return "{$fields['flags']} {$fields['protocol']} {$fields['algorithm']} {$publicKey}";
    }
}
