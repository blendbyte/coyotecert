<?php

use CoyoteCert\Http\Psr18Adapter;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response as PsrResponse;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;

function makeClient(int $status = 200, string $body = '{"ok":true}', array $headers = []): ClientInterface
{
    $factory = new Psr17Factory();
    $stream  = $factory->createStream($body);

    $psrResponse = (new PsrResponse($status, $headers))->withBody($stream);

    $client = new class ($psrResponse) implements ClientInterface {
        public ?RequestInterface $lastRequest = null;

        public function __construct(private readonly \Psr\Http\Message\ResponseInterface $response) {}

        public function sendRequest(RequestInterface $request): \Psr\Http\Message\ResponseInterface
        {
            $this->lastRequest = $request;

            return $this->response;
        }
    };

    return $client;
}

function makeAdapter(int $status = 200, string $body = '{"ok":true}', array $headers = []): Psr18Adapter
{
    $factory = new Psr17Factory();

    return new Psr18Adapter(makeClient($status, $body, $headers), $factory, $factory);
}

it('constructs with explicit factories', function () {
    $factory = new Psr17Factory();
    $adapter = new Psr18Adapter(makeClient(), $factory, $factory);
    expect($adapter)->toBeInstanceOf(Psr18Adapter::class);
});

it('constructs when client implements both factory interfaces', function () {
    // Nyholm Psr17Factory does not implement ClientInterface, so use a combined stub
    $combined = new class implements ClientInterface, \Psr\Http\Message\RequestFactoryInterface, \Psr\Http\Message\StreamFactoryInterface {
        public function sendRequest(RequestInterface $request): \Psr\Http\Message\ResponseInterface
        {
            $factory = new Psr17Factory();

            return $factory->createResponse(200)->withBody($factory->createStream('{}'));
        }

        public function createRequest(string $method, $uri): RequestInterface
        {
            return (new Psr17Factory())->createRequest($method, $uri);
        }

        public function createStream(string $content = ''): \Psr\Http\Message\StreamInterface
        {
            return (new Psr17Factory())->createStream($content);
        }

        public function createStreamFromFile(string $filename, string $mode = 'r'): \Psr\Http\Message\StreamInterface
        {
            return (new Psr17Factory())->createStreamFromFile($filename, $mode);
        }

        public function createStreamFromResource($resource): \Psr\Http\Message\StreamInterface
        {
            return (new Psr17Factory())->createStreamFromResource($resource);
        }
    };

    $adapter = new Psr18Adapter($combined);
    expect($adapter)->toBeInstanceOf(Psr18Adapter::class);
});

it('throws when no request factory is available', function () {
    $clientOnly = new class implements ClientInterface {
        public function sendRequest(RequestInterface $request): \Psr\Http\Message\ResponseInterface
        {
            return (new Psr17Factory())->createResponse(200);
        }
    };

    expect(fn() => new Psr18Adapter($clientOnly))
        ->toThrow(\InvalidArgumentException::class, 'RequestFactoryInterface');
});

it('throws when no stream factory is available', function () {
    $noStream = new class implements ClientInterface, \Psr\Http\Message\RequestFactoryInterface {
        public function sendRequest(RequestInterface $request): \Psr\Http\Message\ResponseInterface
        {
            return (new Psr17Factory())->createResponse(200);
        }

        public function createRequest(string $method, $uri): RequestInterface
        {
            return (new Psr17Factory())->createRequest($method, $uri);
        }
    };

    $factory = new Psr17Factory();
    expect(fn() => new Psr18Adapter($noStream, $factory))
        ->toThrow(\InvalidArgumentException::class, 'StreamFactoryInterface');
});

it('head sends a HEAD request', function () {
    $client  = makeClient();
    $factory = new Psr17Factory();
    $adapter = new Psr18Adapter($client, $factory, $factory);

    $response = $adapter->head('https://acme.example.com');

    expect($client->lastRequest->getMethod())->toBe('HEAD');
    expect($response->getHttpResponseCode())->toBe(200);
});

it('get sends a GET request and decodes JSON body', function () {
    $adapter  = makeAdapter(body: '{"status":"valid"}');
    $response = $adapter->get('https://acme.example.com/dir');

    expect($response->jsonBody())->toBe(['status' => 'valid']);
    expect($response->getHttpResponseCode())->toBe(200);
});

it('get appends query string when arguments are given', function () {
    $client  = makeClient();
    $factory = new Psr17Factory();
    $adapter = new Psr18Adapter($client, $factory, $factory);

    $adapter->get('https://example.com/path', [], ['foo' => 'bar']);

    expect((string) $client->lastRequest->getUri())->toContain('foo=bar');
});

it('get forwards custom headers', function () {
    $client  = makeClient();
    $factory = new Psr17Factory();
    $adapter = new Psr18Adapter($client, $factory, $factory);

    $adapter->get('https://example.com', ['X-Custom: value']);

    expect($client->lastRequest->getHeaderLine('X-Custom'))->toBe('value');
});

it('post sends a POST with JSON body', function () {
    $client  = makeClient(201, '{"id":"abc"}');
    $factory = new Psr17Factory();
    $adapter = new Psr18Adapter($client, $factory, $factory);

    $response = $adapter->post('https://acme.example.com/order', ['domain' => 'example.com']);

    expect($client->lastRequest->getMethod())->toBe('POST');
    expect($client->lastRequest->getHeaderLine('Content-Type'))->toBe('application/jose+json');
    expect($response->getHttpResponseCode())->toBe(201);
    expect($response->jsonBody())->toBe(['id' => 'abc']);
});

it('post forwards custom headers', function () {
    $client  = makeClient();
    $factory = new Psr17Factory();
    $adapter = new Psr18Adapter($client, $factory, $factory);

    $adapter->post('https://example.com', [], ['Replay-Nonce: abc123']);

    expect($client->lastRequest->getHeaderLine('Replay-Nonce'))->toBe('abc123');
});

it('response with non-JSON body is kept as string', function () {
    $adapter  = makeAdapter(body: 'not-json-at-all');
    $response = $adapter->get('https://example.com');

    expect($response->rawBody())->toBe('not-json-at-all');
});

it('response headers are lowercased', function () {
    $adapter  = makeAdapter(headers: ['X-Header' => 'value']);
    $response = $adapter->get('https://example.com');

    expect($response->hasHeader('x-header'))->toBeTrue();
});
