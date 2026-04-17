<?php

use CoyoteCert\Http\Response;

function makeResponse(
    array $headers = [],
    string $url = 'https://example.com',
    ?int $status = 200,
    array|string $body = [],
): Response {
    return new Response(
        headers: $headers,
        requestedUrl: $url,
        statusCode: $status,
        body: $body,
    );
}

it('getHeader returns the header value', function () {
    $r = makeResponse(headers: ['content-type' => 'application/json']);
    expect($r->getHeader('content-type'))->toBe('application/json');
});

it('getHeader returns default when header is missing', function () {
    $r = makeResponse();
    expect($r->getHeader('x-missing', 'fallback'))->toBe('fallback');
    expect($r->getHeader('x-missing'))->toBeNull();
});

it('getHeaders returns all headers', function () {
    $headers = ['a' => '1', 'b' => '2'];
    $r       = makeResponse(headers: $headers);
    expect($r->getHeaders())->toBe($headers);
});

it('hasHeader returns true when header exists', function () {
    $r = makeResponse(headers: ['location' => 'https://example.com/1']);
    expect($r->hasHeader('location'))->toBeTrue();
    expect($r->hasHeader('x-missing'))->toBeFalse();
});

it('getBody returns the body', function () {
    $r = makeResponse(body: ['status' => 'valid']);
    expect($r->getBody())->toBe(['status' => 'valid']);
});

it('getBody returns string body', function () {
    $r = makeResponse(body: 'raw text');
    expect($r->getBody())->toBe('raw text');
});

it('hasBody returns true when body is non-empty', function () {
    expect(makeResponse(body: ['x' => 1])->hasBody())->toBeTrue();
    expect(makeResponse(body: 'hello')->hasBody())->toBeTrue();
});

it('hasBody returns false for empty body', function () {
    expect(makeResponse(body: [])->hasBody())->toBeFalse();
    expect(makeResponse(body: '')->hasBody())->toBeFalse();
});

it('getRequestedUrl returns the URL', function () {
    $r = makeResponse(url: 'https://acme.example.com/dir');
    expect($r->getRequestedUrl())->toBe('https://acme.example.com/dir');
});

it('getHttpResponseCode returns the status code', function () {
    expect(makeResponse(status: 201)->getHttpResponseCode())->toBe(201);
    expect(makeResponse(status: null)->getHttpResponseCode())->toBeNull();
});

it('jsonBody returns the array when body is an array', function () {
    expect(makeResponse(body: ['status' => 'valid'])->jsonBody())->toBe(['status' => 'valid']);
});

it('jsonBody returns empty array when body is a string', function () {
    expect(makeResponse(body: 'raw-pem')->jsonBody())->toBe([]);
});

it('rawBody returns the string when body is a string', function () {
    expect(makeResponse(body: 'raw-pem')->rawBody())->toBe('raw-pem');
});

it('rawBody returns empty string when body is an array', function () {
    expect(makeResponse(body: ['key' => 'val'])->rawBody())->toBe('');
});

it('isJson returns true for array body and false for string body', function () {
    expect(makeResponse(body: ['a' => 1])->isJson())->toBeTrue();
    expect(makeResponse(body: 'text')->isJson())->toBeFalse();
});
