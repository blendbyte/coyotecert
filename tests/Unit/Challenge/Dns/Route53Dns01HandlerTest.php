<?php

use CoyoteCert\Challenge\Dns\Route53Dns01Handler;
use CoyoteCert\Exceptions\ChallengeException;

class TestableRoute53Handler extends Route53Dns01Handler
{
    /** @var list<array{method: string, path: string, queryString: string, body: string}> */
    public array $captured = [];

    /** @var list<string|ChallengeException> */
    private array $queue;

    /** @param list<string|ChallengeException> $queue */
    public function __construct(?string $zoneId, array $queue)
    {
        parent::__construct('AKIDTEST', 'secrettest', $zoneId);
        $this->queue = $queue;
    }

    protected function send(string $method, string $path, string $queryString, string $body): string
    {
        $this->captured[] = compact('method', 'path', 'queryString', 'body');

        $response = array_shift($this->queue);

        if ($response === null) {
            throw new \RuntimeException("Unexpected API call: {$method} {$path}");
        }

        if ($response instanceof \Throwable) {
            throw $response;
        }

        return $response;
    }

    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void {}
}

/**
 * Handler that uses the real send() implementation (with curl stubs) but
 * skips the DNS propagation check so tests run without a live DNS server.
 */
class Route53HandlerWithRealSend extends Route53Dns01Handler
{
    protected function pollForTxtRecord(string $domain, string $keyAuthorization): void {}
}

afterEach(function () {
    unset($GLOBALS['__test_curl']);
});

// ── Fixtures ──────────────────────────────────────────────────────────────────

function r53ZoneListXml(string $id, string $name): string
{
    return '<?xml version="1.0" encoding="UTF-8"?>'
        . '<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
        . '<HostedZones>'
        . '<HostedZone>'
        . '<Id>/hostedzone/' . $id . '</Id>'
        . '<Name>' . $name . '.</Name>'
        . '</HostedZone>'
        . '</HostedZones>'
        . '</ListHostedZonesByNameResponse>';
}

function r53ZoneListEmptyXml(): string
{
    return '<?xml version="1.0" encoding="UTF-8"?>'
        . '<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
        . '<HostedZones/>'
        . '</ListHostedZonesByNameResponse>';
}

function r53ChangeOkXml(): string
{
    return '<?xml version="1.0" encoding="UTF-8"?>'
        . '<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
        . '<ChangeInfo><Id>/change/C123</Id><Status>PENDING</Status></ChangeInfo>'
        . '</ChangeResourceRecordSetsResponse>';
}

// ── deploy() with explicit zone ID ────────────────────────────────────────────

it('deploy skips zone lookup when a zone ID is provided', function () {
    $handler = new TestableRoute53Handler('Z1PA6795UKMFR9', [r53ChangeOkXml()]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured)->toHaveCount(1);
    expect($handler->captured[0]['method'])->toBe('POST');
});

it('deploy strips the /hostedzone/ prefix from an explicit zone ID', function () {
    $handler = new TestableRoute53Handler('/hostedzone/Z1PA6795UKMFR9', [r53ChangeOkXml()]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured[0]['path'])->toContain('/Z1PA6795UKMFR9/');
    expect($handler->captured[0]['path'])->not->toContain('/hostedzone/hostedzone/');
});

it('deploy POSTs to the correct rrset path for the zone', function () {
    $handler = new TestableRoute53Handler('ZTEST123', [r53ChangeOkXml()]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured[0]['path'])->toBe('/2013-04-01/hostedzone/ZTEST123/rrset');
});

it('deploy XML body contains the CREATE action', function () {
    $handler = new TestableRoute53Handler('ZTEST123', [r53ChangeOkXml()]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured[0]['body'])->toContain('<Action>CREATE</Action>');
});

it('deploy XML body sets the record name as a FQDN with trailing dot', function () {
    $handler = new TestableRoute53Handler('ZTEST123', [r53ChangeOkXml()]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured[0]['body'])->toContain('<Name>_acme-challenge.example.com.</Name>');
});

it('deploy XML body sets the FQDN correctly for a subdomain', function () {
    $handler = new TestableRoute53Handler('ZTEST123', [r53ChangeOkXml()]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($handler->captured[0]['body'])->toContain('<Name>_acme-challenge.sub.example.com.</Name>');
});

it('deploy XML body wraps the TXT value in double quotes', function () {
    $handler = new TestableRoute53Handler('ZTEST123', [r53ChangeOkXml()]);

    $handler->deploy('example.com', '', 'my-key-auth');

    expect($handler->captured[0]['body'])->toContain('<Value>&quot;my-key-auth&quot;</Value>');
});

it('deploy XML body sets record type to TXT with TTL 60', function () {
    $handler = new TestableRoute53Handler('ZTEST123', [r53ChangeOkXml()]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured[0]['body'])->toContain('<Type>TXT</Type>');
    expect($handler->captured[0]['body'])->toContain('<TTL>60</TTL>');
});

// ── deploy() with zone auto-detection ─────────────────────────────────────────

it('deploy queries ListHostedZonesByName when no zone ID is provided', function () {
    $handler = new TestableRoute53Handler(null, [
        r53ZoneListXml('Z123', 'example.com'),
        r53ChangeOkXml(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured[0]['method'])->toBe('GET');
    expect($handler->captured[0]['path'])->toBe('/2013-04-01/hostedzone');
    expect($handler->captured[0]['queryString'])->toContain('dnsname=example.com');
    expect($handler->captured[0]['queryString'])->toContain('maxitems=1');
});

it('deploy tries subdomain candidate first then falls back to apex', function () {
    $handler = new TestableRoute53Handler(null, [
        r53ZoneListEmptyXml(),               // sub.example.com → no match
        r53ZoneListXml('Z456', 'example.com'), // example.com    → match
        r53ChangeOkXml(),
    ]);

    $handler->deploy('sub.example.com', '', 'keyauth');

    expect($handler->captured[0]['queryString'])->toContain('dnsname=sub.example.com');
    expect($handler->captured[1]['queryString'])->toContain('dnsname=example.com');
    expect($handler->captured[2]['method'])->toBe('POST');
});

it('deploy caches the detected zone and does not query it again', function () {
    $handler = new TestableRoute53Handler(null, [
        r53ZoneListXml('Z789', 'example.com'),
        r53ChangeOkXml(),
        r53ChangeOkXml(),
    ]);

    $handler->deploy('example.com', '', 'keyauth1');
    $handler->deploy('example.com', '', 'keyauth2');

    $gets = array_filter($handler->captured, fn($c) => $c['method'] === 'GET');
    expect(count($gets))->toBe(1);
});

it('deploy uses the detected zone ID in the POST path', function () {
    $handler = new TestableRoute53Handler(null, [
        r53ZoneListXml('ZABC', 'example.com'),
        r53ChangeOkXml(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured[1]['path'])->toBe('/2013-04-01/hostedzone/ZABC/rrset');
});

it('deploy strips /hostedzone/ prefix from auto-detected zone ID', function () {
    $handler = new TestableRoute53Handler(null, [
        r53ZoneListXml('ZSTRIPPED', 'example.com'),
        r53ChangeOkXml(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');

    expect($handler->captured[1]['path'])->toContain('/ZSTRIPPED/');
    expect($handler->captured[1]['path'])->not->toContain('hostedzone/hostedzone');
});

// ── deploy() error handling ───────────────────────────────────────────────────

it('deploy throws when no zone is found for any candidate', function () {
    $handler = new TestableRoute53Handler(null, [
        r53ZoneListEmptyXml(),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'No Route53 hosted zone found');
});

it('deploy throws when the zone name in the response does not match the candidate', function () {
    $handler = new TestableRoute53Handler(null, [
        r53ZoneListXml('ZOTHER', 'other.com'), // mismatch
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'No Route53 hosted zone found');
});

it('deploy propagates a ChallengeException from the send method', function () {
    $handler = new TestableRoute53Handler('ZTEST', [
        new ChallengeException('Route53 API returned HTTP 403 for POST /2013-04-01/hostedzone/ZTEST/rrset.'),
    ]);

    expect(fn() => $handler->deploy('example.com', '', 'key'))
        ->toThrow(ChallengeException::class, 'HTTP 403');
});

// ── cleanup() ─────────────────────────────────────────────────────────────────

it('cleanup sends a DELETE change batch to the same rrset path', function () {
    $handler = new TestableRoute53Handler('ZCLEAN', [
        r53ChangeOkXml(), // deploy
        r53ChangeOkXml(), // cleanup
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($handler->captured)->toHaveCount(2);
    expect($handler->captured[1]['method'])->toBe('POST');
    expect($handler->captured[1]['path'])->toBe('/2013-04-01/hostedzone/ZCLEAN/rrset');
});

it('cleanup XML body contains the DELETE action', function () {
    $handler = new TestableRoute53Handler('ZCLEAN', [
        r53ChangeOkXml(),
        r53ChangeOkXml(),
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');

    expect($handler->captured[1]['body'])->toContain('<Action>DELETE</Action>');
});

it('cleanup DELETE body reproduces the same name and value as deploy', function () {
    $handler = new TestableRoute53Handler('ZCLEAN', [
        r53ChangeOkXml(),
        r53ChangeOkXml(),
    ]);

    $handler->deploy('example.com', '', 'my-key-auth');
    $handler->cleanup('example.com', '');

    expect($handler->captured[1]['body'])->toContain('<Name>_acme-challenge.example.com.</Name>');
    expect($handler->captured[1]['body'])->toContain('<Value>&quot;my-key-auth&quot;</Value>');
});

it('cleanup is a no-op when deploy was never called for the domain', function () {
    $handler = new TestableRoute53Handler('ZCLEAN', []);

    expect(fn() => $handler->cleanup('example.com', ''))->not->toThrow(\Throwable::class);
    expect($handler->captured)->toBeEmpty();
});

it('cleanup clears the pending record so a second call is a no-op', function () {
    $handler = new TestableRoute53Handler('ZCLEAN', [
        r53ChangeOkXml(), // deploy
        r53ChangeOkXml(), // first cleanup
    ]);

    $handler->deploy('example.com', '', 'keyauth');
    $handler->cleanup('example.com', '');
    $handler->cleanup('example.com', ''); // no extra request

    expect($handler->captured)->toHaveCount(2);
});

// ── send() via real curl stubs ────────────────────────────────────────────────

it('send() throws when curl_init fails', function () {
    $GLOBALS['__test_curl'] = ['init' => false];

    $handler = new Route53HandlerWithRealSend('AKID', 'secret', 'ZTEST');

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->toThrow(ChallengeException::class, 'Failed to initialise cURL for Route53.');
});

it('send() throws when curl reports a connection error', function () {
    $GLOBALS['__test_curl'] = ['body' => false, 'error' => 'Connection refused'];

    $handler = new Route53HandlerWithRealSend('AKID', 'secret', 'ZTEST');

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->toThrow(ChallengeException::class, 'Route53 HTTP request failed: Connection refused');
});

it('send() throws when the API returns HTTP 4xx', function () {
    $GLOBALS['__test_curl'] = ['body' => '<Error/>', 'status' => 403];

    $handler = new Route53HandlerWithRealSend('AKID', 'secret', 'ZTEST');

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->toThrow(ChallengeException::class, 'Route53 API returned HTTP 403');
});

it('send() returns the response body on success', function () {
    $GLOBALS['__test_curl'] = ['body' => r53ChangeOkXml(), 'status' => 200];

    $handler = new Route53HandlerWithRealSend('AKID', 'secret', 'ZTEST');

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->not->toThrow(\Throwable::class);
});

it('send() appends the query string to the URL for GET zone-detection requests', function () {
    // Zone XML is returned for both the GET (zone lookup) and POST (record create).
    // The POST response is ignored by changeRecord(), so this succeeds end-to-end.
    $GLOBALS['__test_curl'] = ['body' => r53ZoneListXml('Z123', 'example.com'), 'status' => 200];

    $handler = new Route53HandlerWithRealSend('AKID', 'secret'); // no zone ID → triggers GET

    expect(fn() => $handler->deploy('example.com', '', 'keyauth'))
        ->not->toThrow(\Throwable::class);
});
