<?php

declare(strict_types=1);

namespace CoyoteCert\DTO;

use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Http\Response;
use CoyoteCert\Support\Arr;

readonly class DomainValidationData
{
    /**
     * @param array{type: string, value: string} $identifier
     * @param array<mixed> $file The http-01 challenge object, empty when not offered
     * @param array<mixed> $dns The dns-01 challenge object, empty when not offered
     * @param array<mixed> $tlsAlpn The tls-alpn-01 challenge object, empty when not offered
     * @param array<mixed> $validationRecord
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
        $identifier = Arr::array($body, 'identifier');
        $challenges = Arr::arrays($body, 'challenges');

        return new self(
            identifier: ['type' => Arr::string($identifier, 'type'), 'value' => Arr::string($identifier, 'value')],
            status: Arr::string($body, 'status'),
            expires: Arr::stringOrNull($body, 'expires'),
            file: self::getValidationByType($challenges, AuthorizationChallengeEnum::HTTP),
            dns: self::getValidationByType($challenges, AuthorizationChallengeEnum::DNS),
            tlsAlpn: self::getValidationByType($challenges, AuthorizationChallengeEnum::TLS_ALPN),
            validationRecord: Arr::array($body, 'validationRecord'),
        );
    }

    /**
     * @param list<array<mixed>> $challenges
     * @return array<mixed>
     */
    private static function getValidationByType(array $challenges, AuthorizationChallengeEnum $authChallenge): array
    {
        foreach ($challenges as $challenge) {
            if (($challenge['type'] ?? '') === $authChallenge->value) {
                return $challenge;
            }
        }

        return [];
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

    /** @return list<array{domainValidationType: string, error: array<mixed>}> */
    public function getErrors(): array
    {
        $errors = [];

        // Only challenges that actually failed: the CA offers every type but the client attempts one
        foreach ([AuthorizationChallengeEnum::HTTP, AuthorizationChallengeEnum::DNS, AuthorizationChallengeEnum::TLS_ALPN] as $type) {
            $data = $this->challengeData($type);
            if (!empty($data['error'])) {
                $errors[] = [
                    'domainValidationType' => $type->value,
                    'error'                => Arr::array($data, 'error'),
                ];
            }
        }

        return $errors;
    }

    /** @return array<mixed> */
    public function challengeData(AuthorizationChallengeEnum $type): array
    {
        return match ($type) {
            AuthorizationChallengeEnum::HTTP     => $this->file,
            AuthorizationChallengeEnum::DNS      => $this->dns,
            AuthorizationChallengeEnum::TLS_ALPN => $this->tlsAlpn,
        };
    }
}
