<?php

namespace CoyoteCert\Challenge\Dns;

use CoyoteCert\Challenge\Dns\Internal\AwsSigV4Signer;
use CoyoteCert\Exceptions\ChallengeException;

/**
 * DNS-01 challenge handler for AWS Route53.
 *
 * Creates and removes _acme-challenge TXT records via the Route53 REST API using
 * AWS Signature Version 4 authentication. No AWS SDK dependency — signing is
 * implemented inline using hash_hmac() / hash().
 *
 * If $zoneId is omitted the hosted zone is resolved automatically by walking the
 * domain's public-suffix candidates and querying ListHostedZonesByName. The zone
 * ID may be supplied with or without the '/hostedzone/' prefix.
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
     * @var array<string, array{0: string, 1: string, 2: string}> domain => [zoneId, recordName, value]
     */
    private array $pendingRecords = [];

    /** @var array<string, string> candidate => zoneId */
    private array $zoneCache = [];

    private AwsSigV4Signer $signer;

    public function __construct(
        string $accessKeyId,
        string $secretAccessKey,
        private readonly ?string $zoneId = null,
    ) {
        $this->signer = new AwsSigV4Signer($accessKeyId, $secretAccessKey, 'us-east-1', 'route53');
    }

    public function deploy(string $domain, string $token, string $keyAuthorization): void
    {
        $zoneId = $this->resolveZoneId($domain);
        $name   = '_acme-challenge.' . $domain . '.';

        $this->changeRecord('CREATE', $zoneId, $name, $keyAuthorization);

        $this->pendingRecords[$domain] = [$zoneId, $name, $keyAuthorization];
        $this->awaitPropagation($domain, $keyAuthorization);
    }

    public function cleanup(string $domain, string $token): void
    {
        if (!isset($this->pendingRecords[$domain])) {
            return;
        }

        [$zoneId, $name, $value] = $this->pendingRecords[$domain];
        $this->changeRecord('DELETE', $zoneId, $name, $value);
        unset($this->pendingRecords[$domain]);
    }

    private function changeRecord(string $action, string $zoneId, string $name, string $value): void
    {
        $path = sprintf('/%s/hostedzone/%s/rrset', self::API_VERSION, $zoneId);
        $this->send('POST', $path, '', $this->buildChangeBatch($action, $name, $value));
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

            $xml   = $this->send('GET', '/' . self::API_VERSION . '/hostedzone', 'dnsname=' . rawurlencode($candidate) . '&maxitems=1', '');
            $zones = $this->parseHostedZones($xml);

            foreach ($zones as $zone) {
                if (rtrim($zone['name'], '.') === $candidate) {
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
     * @return list<array{id: string, name: string}>
     */
    private function parseHostedZones(string $xml): array
    {
        $doc   = new \SimpleXMLElement($xml);
        $zones = [];

        foreach ($doc->HostedZones->HostedZone as $zone) {
            $zones[] = [
                'id'   => str_replace('/hostedzone/', '', (string) $zone->Id),
                'name' => (string) $zone->Name,
            ];
        }

        return $zones;
    }

    private function buildChangeBatch(string $action, string $name, string $value): string
    {
        $escapedName  = htmlspecialchars($name, ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $escapedValue = htmlspecialchars('"' . $value . '"', ENT_XML1 | ENT_QUOTES, 'UTF-8');

        return sprintf(
            '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/%s/">'
            . '<ChangeBatch><Changes><Change>'
            . '<Action>%s</Action>'
            . '<ResourceRecordSet><Name>%s</Name><Type>TXT</Type><TTL>60</TTL>'
            . '<ResourceRecords><ResourceRecord><Value>%s</Value></ResourceRecord></ResourceRecords>'
            . '</ResourceRecordSet>'
            . '</Change></Changes></ChangeBatch>'
            . '</ChangeResourceRecordSetsRequest>',
            self::API_VERSION,
            $action,
            $escapedName,
            $escapedValue,
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
        curl_close($ch);

        if ($raw === false || $error !== '') {
            throw new ChallengeException("Route53 HTTP request failed: {$error}");
        }

        if ($status >= 400) {
            throw new ChallengeException(
                sprintf('Route53 API returned HTTP %d for %s %s.', $status, $method, $path),
            );
        }

        return (string) $raw;
    }

}
