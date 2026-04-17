<?php

namespace CoyoteCert\Interfaces;

use CoyoteCert\Enums\AuthorizationChallengeEnum;

interface ChallengeHandlerInterface
{
    /**
     * Returns true if this handler can deploy the given challenge type.
     */
    public function supports(AuthorizationChallengeEnum $type): bool;

    /**
     * Deploy the challenge so it can be verified by the CA.
     *
     * Semantics differ by challenge type:
     *
     *   http-01  — $token is the filename under /.well-known/acme-challenge/,
     *              $keyAuthorization is the full file contents to serve.
     *
     *   dns-01   — $token is unused; $keyAuthorization is the base64url-encoded
     *              SHA-256 digest to publish as the _acme-challenge TXT record.
     *
     *   dns-persist-01 — same as dns-01; the TXT record must remain until cleanup().
     *
     * @param string $domain The domain being validated.
     * @param string $token Challenge token (http-01 filename; ignored for dns-01).
     * @param string $keyAuthorization Full key authorization (http-01 file body; dns-01 TXT value).
     */
    public function deploy(string $domain, string $token, string $keyAuthorization): void;

    /**
     * Remove the challenge after validation completes (success or failure).
     *
     * @param string $domain The domain that was validated.
     * @param string $token The same token passed to deploy().
     */
    public function cleanup(string $domain, string $token): void;
}
