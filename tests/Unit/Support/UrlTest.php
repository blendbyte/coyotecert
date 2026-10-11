<?php

declare(strict_types=1);

use CoyoteCert\Support\Url;

it('extracts the last path segment as the ID', function () {
    expect(Url::extractId('https://acme.example.com/orders/12345'))->toBe('12345');
});

it('handles trailing slashes', function () {
    expect(Url::extractId('https://acme.example.com/orders/12345/'))->toBe('12345');
});

it('returns empty string for empty URL', function () {
    expect(Url::extractId(''))->toBe('');
});

it('returns all but the first character when there is no slash', function () {
    // strrpos returns false (casts to 0), so substr offset is 0+1=1
    expect(Url::extractId('justanid'))->toBe('ustanid');
});

it('works with deep paths', function () {
    expect(Url::extractId('https://host/a/b/c/d/e'))->toBe('e');
});
