<?php

namespace CoyoteCert\Storage;

readonly class StoredCertificate
{
    public function __construct(
        public string            $certificate,
        public string            $privateKey,
        public string            $fullchain,
        public string            $caBundle,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expiresAt,
        public array             $domains,
    ) {
    }

    public function toArray(): array
    {
        return [
            'certificate' => $this->certificate,
            'private_key' => $this->privateKey,
            'fullchain'   => $this->fullchain,
            'ca_bundle'   => $this->caBundle,
            'issued_at'   => $this->issuedAt->format(\DateTimeInterface::ATOM),
            'expires_at'  => $this->expiresAt->format(\DateTimeInterface::ATOM),
            'domains'     => $this->domains,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            certificate: $data['certificate'],
            privateKey:  $data['private_key'],
            fullchain:   $data['fullchain'],
            caBundle:    $data['ca_bundle'],
            issuedAt:    new \DateTimeImmutable($data['issued_at']),
            expiresAt:   new \DateTimeImmutable($data['expires_at']),
            domains:     $data['domains'],
        );
    }

    public function remainingDays(): int
    {
        $diff = (new \DateTimeImmutable())->diff($this->expiresAt);

        return $diff->invert ? 0 : (int) $diff->days;
    }
}
