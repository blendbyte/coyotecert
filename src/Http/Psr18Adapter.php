<?php

namespace CoyoteCert\Http;

use CoyoteCert\Interfaces\HttpClientInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Adapts any PSR-18 HTTP client to CoyoteCert's internal HttpClientInterface.
 *
 * Both $requestFactory and $streamFactory are optional when the PSR-18 client
 * also implements those interfaces (e.g. Symfony's Psr18Client, nyholm/psr7).
 *
 * Usage:
 *
 *   // Symfony — client implements all three interfaces
 *   CoyoteCert::with(new LetsEncrypt())
 *       ->httpClient(new \Symfony\Component\HttpClient\Psr18Client())
 *       ->issue();
 *
 *   // Guzzle — separate factory required
 *   CoyoteCert::with(new LetsEncrypt())
 *       ->httpClient(new \GuzzleHttp\Client(), new \GuzzleHttp\Psr7\HttpFactory())
 *       ->issue();
 */
class Psr18Adapter implements HttpClientInterface
{
    private RequestFactoryInterface $requestFactory;
    private StreamFactoryInterface $streamFactory;

    public function __construct(
        private readonly ClientInterface $client,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $this->requestFactory = $requestFactory
            ?? ($client instanceof RequestFactoryInterface ? $client
                : throw new \InvalidArgumentException(
                    'Provide a RequestFactoryInterface or use a client that implements it (e.g. Symfony Psr18Client).',
                ));

        $this->streamFactory = $streamFactory
            ?? ($client instanceof StreamFactoryInterface ? $client
                : throw new \InvalidArgumentException(
                    'Provide a StreamFactoryInterface or use a client that implements it (e.g. Symfony Psr18Client).',
                ));
    }

    public function head(string $url): Response
    {
        $request = $this->requestFactory->createRequest('HEAD', $url)
            ->withHeader('User-Agent', 'blendbyte/coyotecert')
            ->withHeader('Accept', 'application/json');

        return $this->send($request, $url);
    }

    /**
     * @param array<int, string> $headers
     * @param array<string, mixed> $arguments
     */
    public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
    {
        if (!empty($arguments)) {
            $url .= '?' . http_build_query($arguments);
        }

        $request = $this->requestFactory->createRequest('GET', $url)
            ->withHeader('User-Agent', 'blendbyte/coyotecert')
            ->withHeader('Accept', 'application/json');

        foreach ($headers as $header) {
            [$name, $value] = explode(':', $header, 2);
            $request        = $request->withAddedHeader(trim($name), trim($value));
        }

        return $this->send($request, $url);
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<int, string> $headers
     */
    public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
    {
        $body    = json_encode($payload, JSON_THROW_ON_ERROR);
        $request = $this->requestFactory->createRequest('POST', $url)
            ->withHeader('User-Agent', 'blendbyte/coyotecert')
            ->withHeader('Accept', 'application/json')
            ->withHeader('Content-Type', 'application/jose+json')
            ->withBody($this->streamFactory->createStream($body));

        foreach ($headers as $header) {
            [$name, $value] = explode(':', $header, 2);
            $request        = $request->withAddedHeader(trim($name), trim($value));
        }

        return $this->send($request, $url);
    }

    private function send(\Psr\Http\Message\RequestInterface $request, string $url): Response
    {
        $psrResponse = $this->client->sendRequest($request);

        $headers = [];
        foreach ($psrResponse->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        $rawBody = (string) $psrResponse->getBody();
        $body    = json_validate($rawBody)
            ? json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR)
            : $rawBody;

        return new Response(
            headers: $headers,
            requestedUrl: $url,
            statusCode: $psrResponse->getStatusCode(),
            body: $body,
        );
    }
}
