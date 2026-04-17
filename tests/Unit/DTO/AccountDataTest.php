<?php

use CoyoteCert\DTO\AccountData;
use CoyoteCert\Http\Response;

function makeAccountResponse(string $locationUrl = 'https://acme.example.com/acct/42'): Response
{
    return new Response(
        headers: ['location' => $locationUrl],
        requestedUrl: 'https://acme.example.com/new-acct',
        statusCode: 201,
        body: [
            'key'       => ['kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB'],
            'status'    => 'valid',
            'agreement' => 'https://letsencrypt.org/tos',
            'createdAt' => '2026-01-01T00:00:00Z',
        ],
    );
}

it('parses an account from a response', function () {
    $account = AccountData::fromResponse(makeAccountResponse());

    expect($account->id)->toBe('42');
    expect($account->url)->toBe('https://acme.example.com/acct/42');
    expect($account->status)->toBe('valid');
    expect($account->agreement)->toBe('https://letsencrypt.org/tos');
    expect($account->createdAt)->toBe('2026-01-01T00:00:00Z');
    expect($account->key)->toBe(['kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB']);
});

it('trims whitespace from the location header', function () {
    $response = new Response(
        headers: ['location' => '  https://acme.example.com/acct/99  '],
        requestedUrl: 'https://acme.example.com/new-acct',
        statusCode: 201,
        body: [
            'key'       => [],
            'status'    => 'valid',
            'agreement' => '',
            'createdAt' => '2026-01-01T00:00:00Z',
        ],
    );

    $account = AccountData::fromResponse($response);
    expect($account->url)->toBe('https://acme.example.com/acct/99');
    expect($account->id)->toBe('99');
});

it('uses empty string for missing agreement', function () {
    $response = new Response(
        headers: ['location' => 'https://acme.example.com/acct/1'],
        requestedUrl: 'https://acme.example.com/new-acct',
        statusCode: 201,
        body: [
            'key'       => [],
            'status'    => 'valid',
            'createdAt' => '2026-01-01T00:00:00Z',
        ],
    );

    $account = AccountData::fromResponse($response);
    expect($account->agreement)->toBe('');
});

it('defaults contact to an empty array when the field is absent', function () {
    $account = AccountData::fromResponse(makeAccountResponse());
    expect($account->contact)->toBe([]);
});

it('parses the contact array when present in the response', function () {
    $response = new Response(
        headers: ['location' => 'https://acme.example.com/acct/42'],
        requestedUrl: 'https://acme.example.com/new-acct',
        statusCode: 201,
        body: [
            'key'       => [],
            'status'    => 'valid',
            'agreement' => '',
            'createdAt' => null,
            'contact'   => ['mailto:admin@example.com'],
        ],
    );

    $account = AccountData::fromResponse($response);
    expect($account->contact)->toBe(['mailto:admin@example.com']);
});

it('fromBody() builds AccountData from a URL and body array without Location header', function () {
    $account = AccountData::fromBody('https://acme.example.com/acct/42', [
        'key'       => ['kty' => 'RSA'],
        'status'    => 'deactivated',
        'agreement' => '',
        'createdAt' => null,
        'contact'   => ['mailto:ops@example.com'],
    ]);

    expect($account->id)->toBe('42');
    expect($account->url)->toBe('https://acme.example.com/acct/42');
    expect($account->status)->toBe('deactivated');
    expect($account->contact)->toBe(['mailto:ops@example.com']);
});
