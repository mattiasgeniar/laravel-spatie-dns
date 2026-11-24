<?php

use React\Dns\Model\Message;
use React\Dns\Model\Record as ResourceRecord;
use React\Dns\Query\Query;
use React\Dns\Query\TimeoutException;
use React\EventLoop\LoopInterface;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;
use Spatie\Dns\Exceptions\CouldNotFetchDns;
use Spatie\Dns\Handlers\Handler;
use Spatie\Dns\Handlers\ReactDns;
use Spatie\Dns\Handlers\UnsupportedRecordType;
use Spatie\Dns\Records\Record;
use Spatie\Dns\Support\Factory;

it('returns the same records as fetching each type on its own', function (bool $throwOnErrorResponse) {
    $handler = (new ScriptedReactDns([
        'A' => scriptedAnswer(records: [
            new ResourceRecord('www.spatie.be', Message::TYPE_CNAME, Message::CLASS_IN, 300, 'spatie.be'),
            new ResourceRecord('spatie.be', Message::TYPE_A, Message::CLASS_IN, 300, '192.0.2.10'),
            new ResourceRecord('spatie.be', Message::TYPE_A, Message::CLASS_IN, 300, '192.0.2.11'),
        ], delay: 0.03),
        'AAAA' => scriptedAnswer(Message::RCODE_NAME_ERROR),
        'NS' => scriptedAnswer(records: [
            new ResourceRecord('spatie.be', Message::TYPE_NS, Message::CLASS_IN, 300, 'ns2.example.com'),
            new ResourceRecord('spatie.be', Message::TYPE_NS, Message::CLASS_IN, 300, 'ns1.example.com'),
        ], delay: 0.01),
        'MX' => scriptedAnswer(records: [
            new ResourceRecord('spatie.be', Message::TYPE_MX, Message::CLASS_IN, 300, ['priority' => 10, 'target' => 'mail.example.com']),
        ], delay: 0.02),
        'TXT' => scriptedAnswer(records: [
            new ResourceRecord('spatie.be', Message::TYPE_TXT, Message::CLASS_IN, 300, ['v=spf1 -all']),
        ]),
    ]))->throwOnErrorResponse($throwOnErrorResponse);

    $types = [DNS_A => 'A', DNS_AAAA => 'AAAA', DNS_NS => 'NS', DNS_MX => 'MX', DNS_TXT => 'txt'];

    $concurrent = array_map('strval', $handler->getRecordsForTypes('www.spatie.be', $types));

    expect($concurrent)->toHaveCount(6)
        ->toBe(array_map('strval', $handler->sequentially('www.spatie.be', $types)));
})->with([true, false]);

it('throws the exception of the first failing type in the requested order', function (array $answers, array $types) {
    $handler = (new ScriptedReactDns($answers))->throwOnErrorResponse(true);

    $sequential = exceptionOf(fn () => $handler->sequentially('spatie.be', $types));
    $concurrent = exceptionOf(fn () => $handler->getRecordsForTypes('spatie.be', $types));

    expect($concurrent)->not->toBeNull()
        ->and($concurrent::class)->toBe($sequential::class)
        ->and($concurrent->getMessage())->toBe($sequential->getMessage())
        ->and($concurrent->responseStatus ?? null)->toBe($sequential->responseStatus ?? null);
})->with([
    'two error statuses, the later type answers first' => [
        [
            'A' => scriptedAnswer(),
            'MX' => scriptedAnswer(Message::RCODE_REFUSED, delay: 0.05),
            'TXT' => scriptedAnswer(Message::RCODE_SERVER_FAILURE),
        ],
        [DNS_A => 'A', DNS_MX => 'MX', DNS_TXT => 'TXT'],
    ],
    'no reply before an error status' => [
        [
            'A' => scriptedAnswer(),
            'MX' => new RuntimeException('Query for spatie.be failed', 0, new TimeoutException('timed out')),
            'TXT' => scriptedAnswer(Message::RCODE_REFUSED),
        ],
        [DNS_A => 'A', DNS_MX => 'MX', DNS_TXT => 'TXT'],
    ],
    'an error status before an unsupported type' => [
        ['A' => scriptedAnswer(), 'MX' => scriptedAnswer(Message::RCODE_REFUSED)],
        [DNS_A => 'A', DNS_MX => 'MX', 0 => 'HINFO'],
    ],
    'an unsupported type before an error status' => [
        ['A' => scriptedAnswer(), 'MX' => scriptedAnswer(Message::RCODE_REFUSED)],
        [DNS_A => 'A', 0 => 'HINFO', DNS_MX => 'MX'],
    ],
]);

it('names the first failing type in the exception', function () {
    $handler = (new ScriptedReactDns([
        'A' => scriptedAnswer(),
        'MX' => scriptedAnswer(Message::RCODE_REFUSED, delay: 0.05),
        'TXT' => scriptedAnswer(Message::RCODE_SERVER_FAILURE),
    ]))->throwOnErrorResponse(true);

    expect(fn () => $handler->getRecordsForTypes('spatie.be', [DNS_A => 'A', DNS_MX => 'MX', DNS_TXT => 'TXT']))
        ->toThrow(fn (CouldNotFetchDns $exception) => expect($exception->responseStatus)->toBe('REFUSED')
            ->and($exception->getMessage())->toContain('spatie.be MX @192.0.2.53'));
});

it('throws an unsupported type after querying the types before it', function () {
    $handler = new ScriptedReactDns(['A' => scriptedAnswer(), 'MX' => scriptedAnswer()]);

    expect(fn () => $handler->getRecordsForTypes('spatie.be', [DNS_A => 'A', 0 => 'HINFO', DNS_MX => 'MX']))
        ->toThrow(UnsupportedRecordType::class)
        ->and($handler->events)->toBe(['sent A @192.0.2.53', 'answered A @192.0.2.53']);
});

it('sends every query before any answer arrives', function () {
    $handler = new ScriptedReactDns([
        'A' => scriptedAnswer(),
        'NS' => scriptedAnswer(),
        'MX' => scriptedAnswer(),
        'TXT' => scriptedAnswer(),
    ]);

    $handler->getRecordsForTypes('spatie.be', [DNS_A => 'A', DNS_NS => 'NS', DNS_MX => 'MX', DNS_TXT => 'TXT']);

    expect(array_slice($handler->events, 0, 4))
        ->toBe(['sent A @192.0.2.53', 'sent NS @192.0.2.53', 'sent MX @192.0.2.53', 'sent TXT @192.0.2.53']);
});

it('takes about as long as the slowest query', function () {
    $handler = new ScriptedReactDns([
        'A' => scriptedAnswer(delay: 0.2),
        'NS' => scriptedAnswer(delay: 0.2),
        'MX' => scriptedAnswer(delay: 0.2),
        'TXT' => scriptedAnswer(delay: 0.3),
    ]);

    $start = microtime(true);

    $handler->getRecordsForTypes('spatie.be', [DNS_A => 'A', DNS_NS => 'NS', DNS_MX => 'MX', DNS_TXT => 'TXT']);

    expect(microtime(true) - $start)->toBeGreaterThanOrEqual(0.3)->toBeLessThan(0.6);
});

it('asks the next nameserver for a type that got no reply, with the same tries', function () {
    $handler = new class(['A' => scriptedAnswer(records: [new ResourceRecord('spatie.be', Message::TYPE_A, Message::CLASS_IN, 300, '192.0.2.10')]), 'MX' => scriptedAnswer(records: [new ResourceRecord('spatie.be', Message::TYPE_MX, Message::CLASS_IN, 300, ['priority' => 10, 'target' => 'mail.example.com'])])]) extends ScriptedReactDns
    {
        protected function systemNameservers(): array
        {
            return ['192.0.2.1', '192.0.2.2', '192.0.2.53'];
        }
    };

    $handler->useNameserver(null)->setRetries(3);

    $types = [DNS_A => 'A', DNS_MX => 'MX'];

    $handler->sequentially('spatie.be', $types);
    $sequential = $handler->sent;

    $handler->sent = [];
    $records = $handler->getRecordsForTypes('spatie.be', $types);

    expect($records)->toHaveCount(2)
        ->and($handler->sent)->toEqualCanonicalizing($sequential)
        ->and($sequential)->toBe([
            'A @192.0.2.1 x3', 'A @192.0.2.2 x1', 'A @192.0.2.53 x1',
            'MX @192.0.2.1 x3', 'MX @192.0.2.2 x1', 'MX @192.0.2.53 x1',
        ]);
});

it('returns the same records as fetching each type on its own from a real nameserver', function () {
    $handler = new class(new Factory) extends ReactDns
    {
        public function sequentially(string $domain, array $types): array
        {
            return Handler::getRecordsForTypes($domain, $types);
        }
    };

    $handler->useNameserver('ns3.cloudflare.com');

    $types = [DNS_A => 'A', DNS_AAAA => 'AAAA', DNS_NS => 'NS', DNS_SOA => 'SOA', DNS_MX => 'MX', DNS_TXT => 'TXT'];

    $concurrent = $handler->getRecordsForTypes('cloudflare.com', $types);
    $sequential = $handler->sequentially('cloudflare.com', $types);

    $typesOf = fn (array $records) => array_map(fn (Record $record) => $record->type(), $records);

    expect($concurrent)->not->toBeEmpty()
        ->and($typesOf($concurrent))->toBe($typesOf($sequential))
        ->and(array_map('strval', $concurrent))->toEqualCanonicalizing(array_map('strval', $sequential));
});

function scriptedAnswer(int $responseCode = Message::RCODE_OK, array $records = [], float $delay = 0.0): array
{
    return ['responseCode' => $responseCode, 'records' => $records, 'delay' => $delay];
}

function exceptionOf(Closure $callback): ?Throwable
{
    try {
        $callback();
    } catch (Throwable $exception) {
        return $exception;
    }

    return null;
}

/**
 * Answers each type with a scripted message after a delay on the loop it is given. Only the
 * nameserver 192.0.2.53 answers; every other nameserver fails as if it did not reply.
 */
class ScriptedReactDns extends ReactDns
{
    /** @var array<int, string> */
    public array $events = [];

    /** @var array<int, string> */
    public array $sent = [];

    /** @param array<string, array|Throwable> $answers */
    public function __construct(protected array $answers)
    {
        parent::__construct(new Factory);

        $this->useNameserver('192.0.2.53');
    }

    public function sequentially(string $domain, array $types): array
    {
        return Handler::getRecordsForTypes($domain, $types);
    }

    protected function sendQuery(Query $query, string $nameserver, int $tries, LoopInterface $loop): PromiseInterface
    {
        $type = array_search($query->type, $this->typeCodes, true);

        $this->events[] = "sent {$type} @{$nameserver}";
        $this->sent[] = "{$type} @{$nameserver} x{$tries}";

        $answer = $this->answers[$type];

        if ($nameserver !== '192.0.2.53') {
            $answer = new RuntimeException('Query failed', 0, new TimeoutException('timed out'));
        }

        $deferred = new Deferred;

        $loop->addTimer(is_array($answer) ? $answer['delay'] : 0.0, function () use ($deferred, $answer, $type, $nameserver): void {
            $this->events[] = "answered {$type} @{$nameserver}";

            if ($answer instanceof Throwable) {
                $deferred->reject($answer);

                return;
            }

            $message = new Message;
            $message->rcode = $answer['responseCode'];
            $message->answers = $answer['records'];

            $deferred->resolve($message);
        });

        return $deferred->promise();
    }
}
