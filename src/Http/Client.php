<?php

namespace CoyoteCert\Http;

use CoyoteCert\Interfaces\HttpClientInterface;
use CurlHandle;

class Client implements HttpClientInterface
{
    public function __construct(
        private int  $timeout = 10,
        private readonly bool $verifyTls = true,
    ) {}

    public function setTimeout(int $seconds): void
    {
        $this->timeout = $seconds;
    }

    public function head(string $url): Response
    {
        return $this->makeCurlRequest('head', $url);
    }

    /**
     * @param array<int, string> $headers
     * @param array<string, mixed> $arguments
     */
    public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
    {
        return $this->makeCurlRequest('get', $url, $headers, $arguments, $maxRedirects);
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<int, string> $headers
     */
    public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
    {
        $headers = array_merge(['Content-Type: application/jose+json'], $headers);

        return $this->makeCurlRequest('post', $url, $headers, $payload, $maxRedirects);
    }

    /**
     * @param array<int, string> $headers
     * @param array<string, mixed> $payload
     */
    private function makeCurlRequest(
        string $httpVerb,
        string $fullUrl,
        array $headers = [],
        array $payload = [],
        int $maxRedirects = 0,
        int $retries = 3,
    ): Response {
        $allHeaders = array_merge([
            'Content-Type: ' . (($httpVerb === 'post') ? 'application/jose+json' : 'application/json'),
        ], $headers);

        $curlHandle = $this->getCurlHandle($fullUrl, $allHeaders, $maxRedirects);

        switch ($httpVerb) {
            case 'head':
                curl_setopt($curlHandle, CURLOPT_CUSTOMREQUEST, 'HEAD');
                curl_setopt($curlHandle, CURLOPT_NOBODY, true);
                break;

            case 'get':
                curl_setopt($curlHandle, CURLOPT_URL, $fullUrl . '?' . http_build_query($payload));
                break;

            case 'post':
                curl_setopt($curlHandle, CURLOPT_POST, true);
                $this->attachRequestPayload($curlHandle, $payload);
                break;
        }

        $curlResult = curl_exec($curlHandle);
        $headerSize = curl_getinfo($curlHandle, CURLINFO_HEADER_SIZE);
        $allHeaders = curl_getinfo($curlHandle);

        $rawResponse = is_string($curlResult) ? $curlResult : '';
        $rawHeaders  = mb_substr($rawResponse, 0, $headerSize);
        $rawBody     = mb_substr($rawResponse, $headerSize);
        $body        = $rawBody;

        $allHeaders = array_merge($allHeaders, $this->parseRawHeaders($rawHeaders));

        if (json_validate($rawBody)) {
            $body = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);
        }

        $httpCode = isset($allHeaders['http_code']) ? (int) $allHeaders['http_code'] : null;

        // Catch HTTP status code 0 when Let's Encrypt API is having problems.
        if ($httpCode === 0) {
            // Retry.
            if ($retries > 0) {
                return $this->makeCurlRequest($httpVerb, $fullUrl, $headers, $payload, $maxRedirects, --$retries);
            }

            // Return 504 Gateway Timeout.
            $httpCode = 504;
        }

        $requestedUrl = isset($allHeaders['url']) ? (string) $allHeaders['url'] : '';

        return new Response($allHeaders, $requestedUrl, $httpCode, $body);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function attachRequestPayload(CurlHandle $curlHandle, array $data): void
    {
        $encoded = json_encode($data, JSON_THROW_ON_ERROR);

        curl_setopt($curlHandle, CURLOPT_POSTFIELDS, $encoded);
    }

    /**
     * @param array<int, string> $headers
     */
    private function getCurlHandle(string $fullUrl, array $headers = [], int $maxRedirects = 0): CurlHandle
    {
        $curlHandle = curl_init($fullUrl);

        if ($curlHandle === false) {
            throw new \RuntimeException('Failed to initialize cURL handle.');
        }

        curl_setopt($curlHandle, CURLOPT_HTTPHEADER, array_merge([
            'Accept: application/json',
        ], $headers));

        curl_setopt($curlHandle, CURLOPT_USERAGENT, 'blendbyte/coyotecert');
        curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curlHandle, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, $this->verifyTls);
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYHOST, $this->verifyTls ? 2 : 0);
        curl_setopt($curlHandle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($curlHandle, CURLOPT_ENCODING, 'gzip, deflate');
        curl_setopt($curlHandle, CURLOPT_HEADER, true);

        if ($maxRedirects > 0) {
            curl_setopt($curlHandle, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($curlHandle, CURLOPT_MAXREDIRS, $maxRedirects);
        }

        return $curlHandle;
    }

    /** @return array<string, string> */
    private function parseRawHeaders(string $rawHeaders): array
    {
        $headers    = explode("\n", $rawHeaders);
        $headersArr = [];

        foreach ($headers as $header) {
            if (!str_contains($header, ':')) {
                continue;
            }

            [$name, $value] = explode(':', $header, 2);

            $headersArr[str_replace('_', '-', strtolower($name))] = trim($value);
        }

        return $headersArr;
    }
}
