<?php

use CoyoteCert\Challenge\Dns\Internal\AwsSigV4Signer;

// ── Shared fixture ─────────────────────────────────────────────────────────────

function makeSigner(): AwsSigV4Signer
{
    return new AwsSigV4Signer('AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', 'us-east-1', 'route53');
}

function fixedNow(): DateTimeImmutable
{
    return new DateTimeImmutable('2024-01-15T12:00:00', new DateTimeZone('UTC'));
}

function defaultSign(): array
{
    return makeSigner()->sign(
        'GET',
        '/2013-04-01/hostedzone',
        'dnsname=example.com&maxitems=1',
        '',
        'application/xml',
        fixedNow(),
    );
}

// ── Return shape ───────────────────────────────────────────────────────────────

it('returns exactly four header keys', function () {
    $headers = defaultSign();

    expect(array_keys($headers))->toBe(['Content-Type', 'Host', 'X-Amz-Date', 'Authorization']);
});

it('Content-Type echoes the supplied content type', function () {
    $headers = makeSigner()->sign('GET', '/', '', '', 'text/plain', fixedNow());

    expect($headers['Content-Type'])->toBe('text/plain');
});

// ── Host header ───────────────────────────────────────────────────────────────

it('Host is service.amazonaws.com', function () {
    $headers = defaultSign();

    expect($headers['Host'])->toBe('route53.amazonaws.com');
});

it('Host uses the service name passed to the constructor', function () {
    $signer  = new AwsSigV4Signer('id', 'secret', 'eu-west-1', 's3');
    $headers = $signer->sign('GET', '/', '', '', 'application/xml', fixedNow());

    expect($headers['Host'])->toBe('s3.amazonaws.com');
});

// ── X-Amz-Date ────────────────────────────────────────────────────────────────

it('X-Amz-Date is formatted as YmdTHisZ', function () {
    $headers = defaultSign();

    expect($headers['X-Amz-Date'])->toBe('20240115T120000Z');
});

it('X-Amz-Date reflects the injected timestamp', function () {
    $now     = new DateTimeImmutable('2023-06-30T23:59:59', new DateTimeZone('UTC'));
    $headers = makeSigner()->sign('GET', '/', '', '', 'application/xml', $now);

    expect($headers['X-Amz-Date'])->toBe('20230630T235959Z');
});

// ── Authorization structure ───────────────────────────────────────────────────

it('Authorization starts with the AWS4-HMAC-SHA256 algorithm', function () {
    $headers = defaultSign();

    expect($headers['Authorization'])->toStartWith('AWS4-HMAC-SHA256 ');
});

it('Authorization contains the access key ID in the Credential', function () {
    $headers = defaultSign();

    expect($headers['Authorization'])->toContain('Credential=AKIDEXAMPLE/');
});

it('Authorization Credential scope is date/region/service/aws4_request', function () {
    $headers = defaultSign();

    expect($headers['Authorization'])->toContain('20240115/us-east-1/route53/aws4_request');
});

it('Authorization lists the signed headers alphabetically', function () {
    $headers = defaultSign();

    expect($headers['Authorization'])->toContain('SignedHeaders=content-type;host;x-amz-date');
});

it('Authorization contains a 64-character hex Signature', function () {
    $headers = defaultSign();

    preg_match('/Signature=([0-9a-f]+)/', $headers['Authorization'], $m);

    expect($m[1])->toHaveLength(64);
});

// ── Determinism and sensitivity ───────────────────────────────────────────────

it('signing is deterministic for the same inputs', function () {
    $a = defaultSign();
    $b = defaultSign();

    expect($a['Authorization'])->toBe($b['Authorization']);
});

it('different timestamps produce different signatures', function () {
    $signer = makeSigner();
    $t1     = new DateTimeImmutable('2024-01-15T12:00:00', new DateTimeZone('UTC'));
    $t2     = new DateTimeImmutable('2024-01-16T12:00:00', new DateTimeZone('UTC'));

    $sig1 = $signer->sign('GET', '/', '', '', 'application/xml', $t1)['Authorization'];
    $sig2 = $signer->sign('GET', '/', '', '', 'application/xml', $t2)['Authorization'];

    expect($sig1)->not->toBe($sig2);
});

it('different secret access keys produce different signatures', function () {
    $s1 = new AwsSigV4Signer('AKID', 'secret-one', 'us-east-1', 'route53');
    $s2 = new AwsSigV4Signer('AKID', 'secret-two', 'us-east-1', 'route53');

    $sig1 = $s1->sign('GET', '/', '', '', 'application/xml', fixedNow())['Authorization'];
    $sig2 = $s2->sign('GET', '/', '', '', 'application/xml', fixedNow())['Authorization'];

    expect($sig1)->not->toBe($sig2);
});

it('different request bodies produce different signatures', function () {
    $signer = makeSigner();

    $sig1 = $signer->sign('POST', '/', '', 'body-a', 'application/xml', fixedNow())['Authorization'];
    $sig2 = $signer->sign('POST', '/', '', 'body-b', 'application/xml', fixedNow())['Authorization'];

    expect($sig1)->not->toBe($sig2);
});

it('different regions produce different signatures', function () {
    $s1 = new AwsSigV4Signer('AKID', 'secret', 'us-east-1', 'route53');
    $s2 = new AwsSigV4Signer('AKID', 'secret', 'eu-west-1', 'route53');

    $sig1 = $s1->sign('GET', '/', '', '', 'application/xml', fixedNow())['Authorization'];
    $sig2 = $s2->sign('GET', '/', '', '', 'application/xml', fixedNow())['Authorization'];

    expect($sig1)->not->toBe($sig2);
});
