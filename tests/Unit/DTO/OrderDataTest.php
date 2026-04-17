<?php

use CoyoteCert\DTO\OrderData;
use CoyoteCert\Http\Response;

function makeOrderResponse(
    string $status = 'pending',
    ?string $certUrl = null,
    string $location = 'https://acme.example.com/order/77',
): Response {
    $body = [
        'status'         => $status,
        'expires'        => '2026-04-20T00:00:00Z',
        'identifiers'    => [['type' => 'dns', 'value' => 'example.com']],
        'authorizations' => ['https://acme.example.com/authz/1'],
        'finalize'       => 'https://acme.example.com/order/77/finalize',
    ];

    if ($certUrl !== null) {
        $body['certificate'] = $certUrl;
    }

    return new Response(
        headers: $location ? ['location' => $location] : [],
        requestedUrl: 'https://acme.example.com/new-order',
        statusCode: 201,
        body: $body,
    );
}

it('parses an order from a response with location header', function () {
    $order = OrderData::fromResponse(makeOrderResponse());

    expect($order->id)->toBe('77');
    expect($order->url)->toBe('https://acme.example.com/order/77');
    expect($order->status)->toBe('pending');
    expect($order->expires)->toBe('2026-04-20T00:00:00Z');
    expect($order->identifiers)->toBe([['type' => 'dns', 'value' => 'example.com']]);
    expect($order->domainValidationUrls)->toBe(['https://acme.example.com/authz/1']);
    expect($order->finalizeUrl)->toBe('https://acme.example.com/order/77/finalize');
    expect($order->certificateUrl)->toBeNull();
});

it('falls back to requestedUrl when location header is absent', function () {
    $order = OrderData::fromResponse(makeOrderResponse(location: ''));

    expect($order->url)->toBe('https://acme.example.com/new-order');
});

it('parses certificateUrl when present', function () {
    $order = OrderData::fromResponse(makeOrderResponse(certUrl: 'https://acme.example.com/cert/1'));

    expect($order->certificateUrl)->toBe('https://acme.example.com/cert/1');
});

it('status helpers return correct boolean values', function () {
    expect(OrderData::fromResponse(makeOrderResponse('pending'))->isPending())->toBeTrue();
    expect(OrderData::fromResponse(makeOrderResponse('ready'))->isReady())->toBeTrue();
    expect(OrderData::fromResponse(makeOrderResponse('valid'))->isValid())->toBeTrue();
    expect(OrderData::fromResponse(makeOrderResponse('invalid'))->isInvalid())->toBeTrue();
});

it('isFinalized returns true when status is valid', function () {
    $order = OrderData::fromResponse(makeOrderResponse('valid'));
    expect($order->isFinalized())->toBeTrue();
    expect($order->isNotFinalized())->toBeFalse();
});

it('isFinalized returns true when finalized flag is set', function () {
    $order = OrderData::fromResponse(makeOrderResponse('processing'))->withFinalized(true);
    expect($order->isFinalized())->toBeTrue();
});

it('isNotFinalized returns true for pending/processing', function () {
    $order = OrderData::fromResponse(makeOrderResponse('pending'));
    expect($order->isNotFinalized())->toBeTrue();
});

it('withCertificateUrl updates url and marks finalized', function () {
    $order = OrderData::fromResponse(makeOrderResponse('processing'))
        ->withCertificateUrl('https://acme.example.com/cert/99');

    expect($order->certificateUrl)->toBe('https://acme.example.com/cert/99');
    expect($order->finalized)->toBeTrue();
});

it('accountUrl is set when passed to fromResponse', function () {
    $order = OrderData::fromResponse(makeOrderResponse(), 'https://acme.example.com/acct/5');
    expect($order->accountUrl)->toBe('https://acme.example.com/acct/5');
});
