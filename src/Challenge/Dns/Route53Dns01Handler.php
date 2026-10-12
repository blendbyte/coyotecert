<?php

declare(strict_types=1);

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\AwsSigV4Signer;
use CoyoteCert\Exceptions\ChallengeException;
use CoyoteCert\Exceptions\HttpChallengeException;

/**
 * DNS-01 challenge handler for AWS Route53.
 *
 * Creates and removes _acme-challenge TXT records via the Route53 REST API using
 * AWS Signature Version 4 authentication. No AWS SDK dependency: signing is
 * implemented inline using hash_hmac() / hash().
 *
 * If $zoneId is omitted the hosted zone is resolved automatically by walking the
 * domain's public-suffix candidates and querying ListHostedZonesByName; private
 * hosted zones are skipped, since the CA can't see them. The zone ID may be
 * supplied with or without the '/hostedzone/' prefix. Pass $sessionToken when
 * using temporary credentials (STS, SSO, EC2/ECS roles).
 *
 * Usage:
 *
 *   new Route53Dns01Handler(accessKeyId: 'AKID', secretAccessKey: 'secret')
 *   new Route53Dns01Handler(accessKeyId: 'AKID', secretAccessKey: 'secret', zoneId: 'Z123')
 *   new Route53Dns01Handler(accessKeyId: 'AKID', secretAccessKey: 'secret')->propagationDelay(30)
 *   new Route53Dns01Handler(accessKeyId: 'AKID', secretAccessKey: 'secret')->skipPropagationCheck()
 */
class Route53Dns01Handler extends AbstractDns01Handler
{
    private const BASE_URL    = 'https://route53.amazonaws.com';
    private const API_VERSION = '2013-04-01';

    /**
     * Records deployed by deploy(), consumed by cleanup().
     *
     * The values are a list: a wildcard and its base name share one identifier
     * and therefore need two TXT values in the same _acme-challenge RRset.
     *
     * @var array<string, array{zoneId: string, name: string, values: list<string>}> domain => rrset
     */
    private array $pendingRecords = [];

    /** @var array<string, string> candidate => zoneId */
    private array $zoneCache = [];

    private AwsSigV4Signer $signer;

    public function __construct(
        string $accessKeyId,
        #[\SensitiveParameter]
        string $secretAccessKey,
        private readonly ?string $zoneId = null,
        #[\SensitiveParameter]
        ?string $sessionToken = null,
    ) {
        $this->signer = new AwsSigV4Signer($accessKeyId, $secretAccessKey, 'us-east-1', 'route53', $sessionToken);
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $this->maybePurgeExisting($domain);

        $zoneId = $this->resolveZoneId($domain);
        $name   = '_acme-challenge.' . $domain . '.';
        $values = $this->pendingRecords[$domain]['values'] ?? [];

        if (!in_array($keyAuthorization, $values, true)) {
            $values[] = $keyAuthorization;
        }

        // UPSERT replaces the whole RRset, so resend every value deployed for this name.
        $this->changeRecord('UPSERT', $zoneId, $name, $values);

        $this->pendingRecords[$domain] = ['zoneId' => $zoneId, 'name' => $name, 'values' => $values];
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        if (!isset($this->pendingRecords[$domain])) {
            return;
        }

        ['zoneId' => $zoneId, 'name' => $name, 'values' => $values] = $this->pendingRecords[$domain];
        $this->changeRecord('DELETE', $zoneId, $name, $values);
        unset($this->pendingRecords[$domain]);
    }

    /**
     * @param list<string> $values
     */
    private function changeRecord(string $action, string $zoneId, string $name, array $values): void
    {
        $path = sprintf('/%s/hostedzone/%s/rrset', self::API_VERSION, $zoneId);
        $this->send('POST', $path, '', $this->buildChangeBatch($action, $name, $values));
    }

    private function resolveZoneId(string $domain): string
    {
        if ($this->zoneId !== null) {
            return str_replace('/hostedzone/', '', $this->zoneId);
        }

        foreach ($this->zoneCandidates($domain) as $candidate) {
            if (isset($this->zoneCache[$candidate])) {
                return $this->zoneCache[$candidate];
            }

            // Listing starts at $candidate in name order, so a public and a private zone of the
            // same name both come first
            $xml   = $this->send('GET', '/' . self::API_VERSION . '/hostedzonesbyname', 'dnsname=' . rawurlencode($candidate) . '&maxitems=10', '');
            $zones = $this->parseHostedZones($xml);

            foreach ($zones as $zone) {
                if (rtrim($zone['name'], '.') === $candidate && !$zone['private']) {
                    $this->zoneCache[$candidate] = $zone['id'];

                    return $zone['id'];
                }
            }
        }

        throw new ChallengeException(
            sprintf('No Route53 hosted zone found for "%s". Verify the credentials have route53:ListHostedZonesByName permission.', $domain),
        );
    }

    /**
     * @return list<array{id: string, name: string, private: bool}>
     */
    private function parseHostedZones(string $xml): array
    {
        $doc   = new \SimpleXMLElement($xml);
        $zones = [];

        foreach ($doc->HostedZones->HostedZone as $zone) {
            $zones[] = [
                'id'      => str_replace('/hostedzone/', '', (string) $zone->Id),
                'name'    => (string) $zone->Name,
                'private' => (string) $zone->Config->PrivateZone === 'true',
            ];
        }

        return $zones;
    }

    /**
     * @param list<string> $values
     */
    private function buildChangeBatch(string $action, string $name, array $values): string
    {
        $escapedName = htmlspecialchars($name, ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $records     = implode('', array_map(
            fn(string $value): string => sprintf(
                '<ResourceRecord><Value>%s</Value></ResourceRecord>',
                htmlspecialchars('"' . $value . '"', ENT_XML1 | ENT_QUOTES, 'UTF-8'),
            ),
            $values,
        ));

        return sprintf(
            '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/%s/">'
            . '<ChangeBatch><Changes><Change>'
            . '<Action>%s</Action>'
            // Route53 has no TTL floor; a short one keeps the challenge set out of resolver caches.
            . '<ResourceRecordSet><Name>%s</Name><Type>TXT</Type><TTL>10</TTL>'
            . '<ResourceRecords>%s</ResourceRecords>'
            . '</ResourceRecordSet>'
            . '</Change></Changes></ChangeBatch>'
            . '</ChangeResourceRecordSetsRequest>',
            self::API_VERSION,
            $action,
            $escapedName,
            $records,
        );
    }

    /**
     * Execute the HTTP call with SigV4-signed headers and return the raw response body.
     *
     * Marked protected so tests can subclass and bypass the network.
     */
    protected function send(string $method, string $path, string $queryString, string $body): string
    {
        $headers = $this->signer->sign(
            $method,
            $path,
            $queryString,
            $body,
            'application/xml',
            new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );

        $url = self::BASE_URL . $path;

        if ($queryString !== '') {
            $url .= '?' . $queryString;
        }

        $curlHeaders = array_map(
            fn(string $name, string $value): string => "{$name}: {$value}",
            array_keys($headers),
            array_values($headers),
        );

        $ch = curl_init($url);

        if ($ch === false) {
            throw new ChallengeException('Failed to initialise cURL for Route53.');
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $curlHeaders,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_USERAGENT      => 'blendbyte/coyotecert',
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $raw    = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error  = curl_error($ch);

        if ($raw === false || $error !== '') {
            throw new ChallengeException("Route53 HTTP request failed: {$error}");
        }

        if ($status >= 400) {
            // AWS explains the failure in <Code>/<Message>, e.g. AccessDenied or InvalidChangeBatch
            $reason = preg_match('~<Code>(.*?)</Code>.*?<Message>(.*?)</Message>~s', (string) $raw, $m)
                ? sprintf(' %s: %s', $m[1], html_entity_decode($m[2], ENT_XML1))
                : '';

            throw new HttpChallengeException(
                sprintf('Route53 API returned HTTP %d for %s %s.%s', $status, $method, $path, $reason),
                $status,
            );
        }

        return (string) $raw;
    }

}
