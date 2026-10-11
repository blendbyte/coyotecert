<?php

namespace CoyoteCert\DTO;

use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;

readonly class DomainValidationData
{
    /**
     * @param array<string, mixed> $identifier
     * @param array<string, mixed> $file
     * @param array<string, mixed> $dns
     * @param array<string, mixed> $tlsAlpn
     * @param array<string, mixed> $validationRecord
     */
    public function __construct(
        public array $identifier,
        public string $status,
        public ?string $expires,
        public array $file,
        public array $dns,
        public array $tlsAlpn = [],
        public array $validationRecord = [],
    ) {}

    public static function fromResponse(Response $response): DomainValidationData
    {
        $body       = $response->jsonBody();
        $challenges = $body['challenges'];

        return new self(
            identifier: $body['identifier'],
            status: $body['status'],
            expires: $body['expires'] ?? null,
            file: self::getValidationByType($challenges, AuthorizationChallengeEnum::HTTP),
            dns: self::getValidationByType($challenges, AuthorizationChallengeEnum::DNS),
            tlsAlpn: self::getValidationByType($challenges, AuthorizationChallengeEnum::TLS_ALPN),
            validationRecord: Arr::get($body, 'validationRecord', []),
        );
    }

    /**
     * @param array<int, array<string, mixed>> $haystack
     * @return array<string, mixed>
     */
    private static function getValidationByType(array $haystack, AuthorizationChallengeEnum $authChallenge): array
    {
        $matches = array_values(array_filter(
            $haystack,
            static fn(array $entry) => ($entry['type'] ?? '') === $authChallenge->value,
        ));

        return $matches[0] ?? [];
    }

    public function isPending(): bool
    {
        return $this->status === 'pending';
    }

    public function isValid(): bool
    {
        return $this->status === 'valid';
    }

    public function isInvalid(): bool
    {
        return $this->status === 'invalid';
    }

    public function hasErrors(): bool
    {
        foreach ([AuthorizationChallengeEnum::HTTP, AuthorizationChallengeEnum::DNS, AuthorizationChallengeEnum::TLS_ALPN] as $type) {
            $data = $this->challengeData($type);
            if (!empty($data['error'])) {
                return true;
            }
        }

        return false;
    }

    /** @return array<int, array<string, mixed>> */
    public function getErrors(): array
    {
        $errors = [];

        // Only challenges that actually failed: the CA offers every type but the client attempts one
        foreach ([AuthorizationChallengeEnum::HTTP, AuthorizationChallengeEnum::DNS, AuthorizationChallengeEnum::TLS_ALPN] as $type) {
            $data = $this->challengeData($type);
            if (!empty($data['error'])) {
                $errors[] = [
                    'domainValidationType' => $type->value,
                    'error'                => Arr::get($data, 'error'),
                ];
            }
        }

        return $errors;
    }

    /** @return array<string, mixed> */
    public function challengeData(AuthorizationChallengeEnum $type): array
    {
        return match ($type) {
            AuthorizationChallengeEnum::HTTP     => $this->file,
            AuthorizationChallengeEnum::DNS      => $this->dns,
            AuthorizationChallengeEnum::TLS_ALPN => $this->tlsAlpn,
        };
    }
}
