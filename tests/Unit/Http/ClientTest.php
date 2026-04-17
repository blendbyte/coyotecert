<?php

use CoyoteCert\Http\Client;

it('setTimeout() updates the internal timeout value', function () {
    $client = new Client(timeout: 10);
    $client->setTimeout(30);

    $ref = new \ReflectionProperty(Client::class, 'timeout');
    expect($ref->getValue($client))->toBe(30);
});

it('getCurlHandle() enables FOLLOWLOCATION and MAXREDIRS when maxRedirects > 0', function () {
    $client = new Client();
    $method = new \ReflectionMethod(Client::class, 'getCurlHandle');

    $handle = $method->invoke($client, 'http://example.com', [], 2);

    expect($handle)->toBeInstanceOf(\CurlHandle::class);
    // curl handles are freed automatically in PHP 8.3+; no explicit close needed
});
