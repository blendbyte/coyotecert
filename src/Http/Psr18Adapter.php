<?php

declare(strict_types=1);

namespace CoyoteCert\Http;

use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Interfaces\HttpClientInterface;
use Psr\Http\Client\ClientExceptionInterface;
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
 *   // Symfony: the client implements all three interfaces
 *   CoyoteCert::with(new LetsEncrypt())
 *       ->httpClient(new \Symfony\Component\HttpClient\Psr18Client())
 *       ->issue();
 *
 *   // Guzzle: a separate factory is required
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
            if (!str_contains($header, ':')) {
                continue;
            }
            [$name, $value] = explode(':', $header, 2);
            $request        = $request->withHeader(trim($name), trim($value));
        }

        $response = $this->send($request, $url);

        // Follow redirects ourselves: PSR-18 clients differ (Guzzle doesn't follow them in sendRequest())
        for ($i = 0; $i < $maxRedirects && in_array($response->getHttpResponseCode(), [301, 302, 303, 307, 308], true); $i++) {
            $location = $response->getHeaderLine('location');

            if ($location === '') {
                break;
            }

            // A relative Location is resolved against the current scheme and host
            $uri = $request->getUri();
            $url = preg_match('~^https?://~i', $location)
                ? $location
                : sprintf('%s://%s/%s', $uri->getScheme(), $uri->getAuthority(), ltrim($location, '/'));
            $request  = $request->withUri($this->requestFactory->createRequest('GET', $url)->getUri());
            $response = $this->send($request, $url);
        }

        return $response;
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
            if (!str_contains($header, ':')) {
                continue;
            }
            [$name, $value] = explode(':', $header, 2);
            $request        = $request->withHeader(trim($name), trim($value));
        }

        return $this->send($request, $url);
    }

    private function send(\Psr\Http\Message\RequestInterface $request, string $url): Response
    {
        try {
            $psrResponse = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            // Same contract as the curl client: transport failures are AcmeExceptions
            throw new AcmeException(sprintf('%s %s failed: %s', $request->getMethod(), $url, $e->getMessage()), previous: $e);
        }

        $headers = [];
        foreach ($psrResponse->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        $rawBody = (string) $psrResponse->getBody();
        $decoded = json_validate($rawBody) ? json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR) : null;
        $body    = is_array($decoded) ? $decoded : $rawBody;

        return new Response(
            headers: $headers,
            requestedUrl: $url,
            statusCode: $psrResponse->getStatusCode(),
            body: $body,
        );
    }
}
