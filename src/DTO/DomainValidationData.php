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
     * @param array<string, mixed> $dnsPersist
     * @param array<string, mixed> $validationRecord
     */
    public function __construct(
        public array $identifier,
        public string $status,
        public string $expires,
        public array $file,
        public array $dns,
        public array $dnsPersist,
        public array $validationRecord,
    ) {}

    public static function fromResponse(Response $response): DomainValidationData
    {
        $body       = $response->jsonBody();
        $challenges = $body['challenges'];

        return new self(
            identifier: $body['identifier'],
            status: $body['status'],
            expires: $body['expires'],
            file: self::getValidationByType($challenges, AuthorizationChallengeEnum::HTTP),
            dns: self::getValidationByType($challenges, AuthorizationChallengeEnum::DNS),
            dnsPersist: self::getValidationByType($challenges, AuthorizationChallengeEnum::DNS_PERSIST),
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
        foreach ([AuthorizationChallengeEnum::HTTP, AuthorizationChallengeEnum::DNS, AuthorizationChallengeEnum::DNS_PERSIST] as $type) {
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
        if (!$this->hasErrors()) {
            return [];
        }

        $errors = [];

        foreach ([AuthorizationChallengeEnum::HTTP, AuthorizationChallengeEnum::DNS, AuthorizationChallengeEnum::DNS_PERSIST] as $type) {
            $data = $this->challengeData($type);
            if (!empty($data)) {
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
            AuthorizationChallengeEnum::HTTP        => $this->file,
            AuthorizationChallengeEnum::DNS         => $this->dns,
            AuthorizationChallengeEnum::DNS_PERSIST => $this->dnsPersist,
        };
    }
}
