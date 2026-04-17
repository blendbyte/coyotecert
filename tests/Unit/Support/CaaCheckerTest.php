<?php

use CoyoteCert\Exceptions\CaaException;
use CoyoteCert\Support\CaaChecker;
use Spatie\Dns\Records\CAA;

// ── helpers ───────────────────────────────────────────────────────────────────

function makeCaaRecord(string $tag, string $value, int $flag = 0): CAA
{
    return CAA::make([
        'host'  => 'example.com',
        'ttl'   => 300,
        'class' => 'IN',
        'type'  => 'CAA',
        'flag'  => $flag,
        'tag'   => $tag,
        'value' => $value,
    ]);
}

/**
 * Build a CaaChecker whose resolver returns $records for every domain.
 *
 * @param CAA[]|array<string, CAA[]> $recordsOrMap Either a flat array (same records for all
 *                                                 domains) or a domain-keyed map.
 */
function makeChecker(array $recordsOrMap = []): CaaChecker
{
    $isMap = array_keys($recordsOrMap) !== range(0, count($recordsOrMap) - 1)
        && !empty($recordsOrMap)
        && is_string(array_key_first($recordsOrMap));

    return new CaaChecker(static function (string $domain) use ($recordsOrMap, $isMap): array {
        if ($isMap) {
            return $recordsOrMap[$domain] ?? [];
        }

        return $recordsOrMap;
    });
}

// ── no CAA records → any CA permitted ────────────────────────────────────────

it('passes when no CAA records exist for the domain', function () {
    $checker = makeChecker([]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

// ── matching CA identifier ────────────────────────────────────────────────────

it('passes when a CAA issue record permits the CA', function () {
    $checker = makeChecker([makeCaaRecord('issue', 'letsencrypt.org')]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

it('passes when the CA identifier appears among multiple permitted CAs', function () {
    $checker = makeChecker([
        makeCaaRecord('issue', 'digicert.com'),
        makeCaaRecord('issue', 'letsencrypt.org'),
    ]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

// ── blocked CA ────────────────────────────────────────────────────────────────

it('throws CaaException when the CA is not in any issue record', function () {
    $checker = makeChecker([makeCaaRecord('issue', 'digicert.com')]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))->toThrow(CaaException::class);
});

it('CaaException message includes the queried domain', function () {
    $checker = makeChecker([makeCaaRecord('issue', 'digicert.com')]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))
        ->toThrow(CaaException::class, 'example.com');
});

it('CaaException message lists the expected CA identifiers', function () {
    $checker = makeChecker([makeCaaRecord('issue', 'digicert.com')]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))
        ->toThrow(CaaException::class, 'letsencrypt.org');
});

// ── wildcard domains ──────────────────────────────────────────────────────────

it('passes for wildcard when an issuewild record permits the CA', function () {
    $checker = makeChecker([makeCaaRecord('issuewild', 'letsencrypt.org')]);
    expect(fn() => $checker->check(['*.example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

it('falls back to issue records for wildcards when no issuewild record exists', function () {
    $checker = makeChecker([makeCaaRecord('issue', 'letsencrypt.org')]);
    expect(fn() => $checker->check(['*.example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

it('throws for wildcard when issuewild record blocks the CA', function () {
    $checker = makeChecker([makeCaaRecord('issuewild', 'digicert.com')]);
    expect(fn() => $checker->check(['*.example.com'], ['letsencrypt.org']))->toThrow(CaaException::class);
});

it('does not use issuewild records when checking a non-wildcard domain', function () {
    // Only an issuewild record, no issue record → no restriction on non-wildcard
    $checker = makeChecker([makeCaaRecord('issuewild', 'digicert.com')]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

// ── CAA record value with parameters ─────────────────────────────────────────

it('ignores parameter extensions after a semicolon in the CAA value', function () {
    $checker = makeChecker([makeCaaRecord('issue', 'letsencrypt.org; validationmethods=http-01')]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

it('strips surrounding quotes from the CAA value', function () {
    $checker = makeChecker([makeCaaRecord('issue', '"letsencrypt.org"')]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

// ── iodef-only records ────────────────────────────────────────────────────────

it('passes when only iodef records are present (no issue restriction)', function () {
    $checker = makeChecker([makeCaaRecord('iodef', 'mailto:abuse@example.com')]);
    expect(fn() => $checker->check(['example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

// ── tree walk ─────────────────────────────────────────────────────────────────

it('walks up to the parent domain when no records exist on the subdomain', function () {
    // sub.example.com has no CAA; example.com blocks the CA
    $checker = makeChecker([
        'sub.example.com' => [],
        'example.com'     => [makeCaaRecord('issue', 'digicert.com')],
    ]);
    expect(fn() => $checker->check(['sub.example.com'], ['letsencrypt.org']))->toThrow(CaaException::class);
});

it('stops walking when records are found at the subdomain level', function () {
    // sub.example.com permits the CA; example.com blocks it — subdomain wins
    $checker = makeChecker([
        'sub.example.com' => [makeCaaRecord('issue', 'letsencrypt.org')],
        'example.com'     => [makeCaaRecord('issue', 'digicert.com')],
    ]);
    expect(fn() => $checker->check(['sub.example.com'], ['letsencrypt.org']))->not->toThrow(CaaException::class);
});

// ── empty caIdentifiers → skip check ─────────────────────────────────────────

it('skips the check when caIdentifiers is empty', function () {
    // Even with blocking records, an empty identifier list means "skip"
    $checker = makeChecker([makeCaaRecord('issue', 'digicert.com')]);
    expect(fn() => $checker->check(['example.com'], []))->not->toThrow(CaaException::class);
});

// ── multiple domains ──────────────────────────────────────────────────────────

it('checks every domain and throws on the first blocked one', function () {
    $checker = makeChecker([
        'ok.example.com'      => [makeCaaRecord('issue', 'letsencrypt.org')],
        'blocked.example.com' => [makeCaaRecord('issue', 'digicert.com')],
    ]);
    expect(fn() => $checker->check(['ok.example.com', 'blocked.example.com'], ['letsencrypt.org']))
        ->toThrow(CaaException::class, 'blocked.example.com');
});
