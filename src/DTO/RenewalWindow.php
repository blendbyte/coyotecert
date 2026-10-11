<?php

namespace CoyoteCert\DTO;

use DateTimeImmutable;

readonly class RenewalWindow
{
    public function __construct(
        public DateTimeImmutable $start,
        public DateTimeImmutable $end,
        public ?string           $explanationUrl = null,
    ) {}

    /**
     * True once the window has started. A window that has already ended still counts:
     * RFC 9773 §4.2 says to renew immediately, and CAs move the window into the past
     * for certificates they are about to revoke.
     */
    public function isOpen(): bool
    {
        return new DateTimeImmutable() >= $this->start;
    }
}
