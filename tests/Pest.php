<?php

// ── Override sleep() in the Endpoints namespace (unit tests only) ────────────
// Polling loops in DomainValidation::allChallengesPassed() and
// Order::waitUntilValid() call sleep() without a namespace prefix, so PHP
// first looks for a function in the current (CoyoteCert\Endpoints) namespace.
// Defining one here turns every sleep() call in that namespace into a no-op,
// keeping unit tests fast.
//
// We only do this when the Unit testsuite is active — integration tests must
// use the real sleep() so Pebble has time to process validations between polls.

namespace CoyoteCert\Endpoints {
    function sleep(int $seconds): void
    {
        if (!defined('COYOTE_INTEGRATION_TESTS')) {
            return; // no-op for unit tests
        }

        \sleep($seconds); // real sleep for integration tests
    }
}

// ── Override sleep() in the Challenge\Dns namespace (unit tests only) ─────────
// pollForTxtRecord() and awaitPropagation() call sleep() for poll intervals and
// optional fixed delays. Same no-op trick keeps DNS handler unit tests instant.

namespace CoyoteCert\Challenge\Dns {
    function sleep(int $seconds): void
    {
        if (!defined('COYOTE_INTEGRATION_TESTS')) {
            return; // no-op for unit tests
        }

        \sleep($seconds); // real sleep for integration tests
    }
}

// ── Global helpers ────────────────────────────────────────────────────────────

namespace {

    use CoyoteCert\Provider\Pebble;
    use Tests\TestCase;

    pest()->extend(TestCase::class)->in('Unit', 'Integration');

    // Mark the integration test processes so the sleep() override in
    // CoyoteCert\Endpoints stays real (Pebble needs actual wait time between polls).
    pest()->beforeAll(function () {
        define('COYOTE_INTEGRATION_TESTS', true);
    })->in('Integration');

    // ── Shared key fixtures (pre-generated to avoid macOS EC key generation issues) ──

    function rsaKeyPem(): string
    {
        openssl_pkey_export(
            openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]),
            $pem,
        );

        return $pem;
    }

    function ecKeyPem(string $curve = 'prime256v1'): string
    {
        return match ($curve) {
            'prime256v1' => "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHaR0sCEL8isElEhAhPAsqrogUVVqP+uvX8Bf9zsjALqoAoGCCqGSM49\nAwEHoUQDQgAEN2q6j/MaE8CZ6KLmpR5ocW26YOXvVgiuIuIpouGek2Bu67BBpDRs\nG17vInzVc/P0R01RhthIrIahxR2OdxbkZw==\n-----END EC PRIVATE KEY-----",
            'secp384r1'  => "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDDgub3rNdQD28MtMUkOsFxxDIlS5mzPotXUzl/5IQLTd0oGtNdbovij\nV6H+2jzWT66gBwYFK4EEACKhZANiAAR+uI186ZeIR46EbYd7XRLWI4fotezzHLUS\noaF73Sp236v453E4W/V7QnMevfA3WtLnrhb7F1IATQLGO4f1skqmMSqHYXzRSLOW\nCejQifvrz0TqrkyVdK9e7uq36NPEDDw=\n-----END EC PRIVATE KEY-----",
            'secp521r1'  => "-----BEGIN EC PRIVATE KEY-----\nMIHcAgEBBEIBn7Elzxkr+b9LEKfx/wxC7/g+hqiiI+OsrXp4CGNOgiCy+B6yQFI8\nuUB41kdrTzsd0YFnDhiKkx256WDxap2rEs6gBwYFK4EEACOhgYkDgYYABADV+WWz\neq1sbiBK5IJkT4AcV14E8tw8h2uE7Oz3RHF//MoGQlAeZJZ2a/e5nrzbCxVV8ySz\nNsWw/Ye7ErDbvPZb6gCxUemjdn7hVHrnbqoDgDJXlcSI0QtSHQcb3C9ifjxCqhvl\nhzyCoKJdVpqaJk8ArxBh1sLbDLrXREZyXseGAWjteQ==\n-----END EC PRIVATE KEY-----",
            default      => throw new \InvalidArgumentException("Unknown curve: $curve"),
        };
    }

    // ── Pebble integration test helpers ──────────────────────────────────────────

    /**
     * Returns true when a Pebble CA is reachable at PEBBLE_URL (or the default
     * localhost address). Used as the ->skip() guard for integration tests so they
     * run automatically in CI (where Pebble starts as a service) and are skipped
     * gracefully on developer machines without a local Pebble instance.
     */
    function pebbleAvailable(): bool
    {
        static $result = null;

        if ($result === null) {
            $envUrl = getenv('PEBBLE_URL');

            if ($envUrl !== false && $envUrl !== '') {
                // PEBBLE_URL explicitly set (e.g. CI) — trust that Pebble is up
                $result = true;
            } else {
                // No env var — probe the default localhost address
                $ch = curl_init('https://localhost:14000/dir');
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_SSL_VERIFYHOST => false,
                    CURLOPT_TIMEOUT        => 3,
                    CURLOPT_CONNECTTIMEOUT => 2,
                ]);
                curl_exec($ch);
                $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                $result = $code > 0;
            }
        }

        return $result;
    }

    function pebble(): Pebble
    {
        return new Pebble(
            url: getenv('PEBBLE_URL') ?: 'https://localhost:14000/dir',
            verifyTls: false,
        );
    }

} // end namespace {}
