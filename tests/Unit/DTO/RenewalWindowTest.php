<?php

use CoyoteCert\DTO\RenewalWindow;

it('isOpen returns true when now is inside the window', function () {
    $window = new RenewalWindow(
        start: new DateTimeImmutable('-1 hour'),
        end:   new DateTimeImmutable('+1 hour'),
    );

    expect($window->isOpen())->toBeTrue();
});

it('isOpen returns false when now is before the window', function () {
    $window = new RenewalWindow(
        start: new DateTimeImmutable('+1 day'),
        end:   new DateTimeImmutable('+2 days'),
    );

    expect($window->isOpen())->toBeFalse();
});

it('isOpen returns false when now is after the window', function () {
    $window = new RenewalWindow(
        start: new DateTimeImmutable('-2 days'),
        end:   new DateTimeImmutable('-1 day'),
    );

    expect($window->isOpen())->toBeFalse();
});

it('exposes start, end, and explanationUrl', function () {
    $start  = new DateTimeImmutable('2026-01-01T00:00:00Z');
    $end    = new DateTimeImmutable('2026-01-07T00:00:00Z');
    $window = new RenewalWindow(start: $start, end: $end, explanationUrl: 'https://example.com');

    expect($window->start)->toBe($start);
    expect($window->end)->toBe($end);
    expect($window->explanationUrl)->toBe('https://example.com');
});

it('explanationUrl defaults to null', function () {
    $window = new RenewalWindow(
        start: new DateTimeImmutable(),
        end:   new DateTimeImmutable('+1 hour'),
    );

    expect($window->explanationUrl)->toBeNull();
});
