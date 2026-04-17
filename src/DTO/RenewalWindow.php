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

    public function isOpen(): bool
    {
        $now = new DateTimeImmutable();

        return $now >= $this->start && $now <= $this->end;
    }
}
