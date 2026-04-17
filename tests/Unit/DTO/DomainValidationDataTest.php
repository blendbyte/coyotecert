<?php

use CoyoteCert\DTO\DomainValidationData;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Http\Response;

function makeDvResponse(
    string $status = 'pending',
    array $extraChallenges = [],
    array $extraBody = [],
): Response {
    $challenges = array_merge([
        ['type' => 'http-01',  'token' => 'tok-http',  'url' => 'https://acme.example.com/chall/1'],
        ['type'                => 'dns-01',   'token' => 'tok-dns',   'url' => 'https://acme.example.com/chall/2',
            'keyAuthorization' => 'tok-dns.thumb'],
    ], $extraChallenges);

    return new Response(
        headers: [],
        requestedUrl: 'https://acme.example.com/authz/1',
        statusCode: 200,
        body: array_merge([
            'identifier' => ['type' => 'dns', 'value' => 'example.com'],
            'status'     => $status,
            'expires'    => '2026-04-20T00:00:00Z',
            'challenges' => $challenges,
        ], $extraBody),
    );
}

it('parses identifier, status, and expires', function () {
    $dv = DomainValidationData::fromResponse(makeDvResponse());

    expect($dv->identifier)->toBe(['type' => 'dns', 'value' => 'example.com']);
    expect($dv->status)->toBe('pending');
    expect($dv->expires)->toBe('2026-04-20T00:00:00Z');
});

it('challengeData returns http-01 data', function () {
    $dv   = DomainValidationData::fromResponse(makeDvResponse());
    $data = $dv->challengeData(AuthorizationChallengeEnum::HTTP);

    expect($data['type'])->toBe('http-01');
    expect($data['token'])->toBe('tok-http');
});

it('challengeData returns dns-01 data', function () {
    $dv   = DomainValidationData::fromResponse(makeDvResponse());
    $data = $dv->challengeData(AuthorizationChallengeEnum::DNS);

    expect($data['type'])->toBe('dns-01');
    expect($data['token'])->toBe('tok-dns');
});

it('challengeData returns empty array when dns-persist-01 is not in response', function () {
    $dv   = DomainValidationData::fromResponse(makeDvResponse());
    $data = $dv->challengeData(AuthorizationChallengeEnum::DNS_PERSIST);

    expect($data)->toBe([]);
});

it('challengeData returns dns-persist-01 data when present', function () {
    $dv = DomainValidationData::fromResponse(makeDvResponse(extraChallenges: [
        ['type' => 'dns-persist-01', 'token' => 'tok-persist', 'url' => 'https://acme.example.com/chall/3'],
    ]));

    $data = $dv->challengeData(AuthorizationChallengeEnum::DNS_PERSIST);
    expect($data['type'])->toBe('dns-persist-01');
    expect($data['token'])->toBe('tok-persist');
});

it('status helpers return correct values', function () {
    expect(DomainValidationData::fromResponse(makeDvResponse('pending'))->isPending())->toBeTrue();
    expect(DomainValidationData::fromResponse(makeDvResponse('valid'))->isValid())->toBeTrue();
    expect(DomainValidationData::fromResponse(makeDvResponse('invalid'))->isInvalid())->toBeTrue();
});

it('hasErrors returns false when no errors present', function () {
    expect(DomainValidationData::fromResponse(makeDvResponse())->hasErrors())->toBeFalse();
});

it('hasErrors returns true when a challenge has an error', function () {
    // Override the http-01 challenge with one that carries an error (dns-01 type so no duplicate)
    $dv = DomainValidationData::fromResponse(new Response(
        headers: [],
        requestedUrl: 'https://acme.example.com/authz/1',
        statusCode: 200,
        body: [
            'identifier' => ['type' => 'dns', 'value' => 'example.com'],
            'status'     => 'invalid',
            'expires'    => '2026-04-20T00:00:00Z',
            'challenges' => [
                ['type'     => 'http-01', 'token' => 'tok-http',
                    'error' => ['type' => 'urn:ietf:params:acme:error:connection', 'detail' => 'refused']],
            ],
        ],
    ));

    expect($dv->hasErrors())->toBeTrue();
});

it('getErrors returns empty array when no errors', function () {
    expect(DomainValidationData::fromResponse(makeDvResponse())->getErrors())->toBe([]);
});

it('getErrors includes error entries', function () {
    $dv = DomainValidationData::fromResponse(new Response(
        headers: [],
        requestedUrl: 'https://acme.example.com/authz/1',
        statusCode: 200,
        body: [
            'identifier' => ['type' => 'dns', 'value' => 'example.com'],
            'status'     => 'invalid',
            'expires'    => '2026-04-20T00:00:00Z',
            'challenges' => [
                ['type'     => 'http-01', 'token' => 'tok',
                    'error' => ['type' => 'urn:ietf:params:acme:error:connection', 'detail' => 'refused']],
            ],
        ],
    ));

    $errors = $dv->getErrors();
    expect($errors)->toHaveCount(1);
    expect($errors[0]['domainValidationType'])->toBe('http-01');
    expect($errors[0]['error'])->not->toBeEmpty();
});

it('validationRecord defaults to empty array when absent', function () {
    $dv = DomainValidationData::fromResponse(makeDvResponse());
    expect($dv->validationRecord)->toBe([]);
});

it('validationRecord is populated when present', function () {
    $dv = DomainValidationData::fromResponse(makeDvResponse(extraBody: [
        'validationRecord' => [['url' => 'http://example.com', 'statusCode' => '200']],
    ]));

    expect($dv->validationRecord)->toHaveCount(1);
});
