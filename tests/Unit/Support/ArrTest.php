<?php

declare(strict_types=1);

use CoyoteCert\Support\Arr;

it('accessible returns true for plain arrays', function () {
    expect(Arr::accessible([]))->toBeTrue();
    expect(Arr::accessible(['a' => 1]))->toBeTrue();
});

it('accessible returns true for ArrayAccess objects', function () {
    $obj = new ArrayObject(['x' => 1]);
    expect(Arr::accessible($obj))->toBeTrue();
});

it('accessible returns false for non-array scalars', function () {
    expect(Arr::accessible('string'))->toBeFalse();
    expect(Arr::accessible(42))->toBeFalse();
    expect(Arr::accessible(null))->toBeFalse();
});

it('exists returns true when key is present in array', function () {
    expect(Arr::exists(['a' => 1], 'a'))->toBeTrue();
    expect(Arr::exists(['a' => null], 'a'))->toBeTrue();
});

it('exists returns false when key is absent from array', function () {
    expect(Arr::exists([], 'a'))->toBeFalse();
    expect(Arr::exists(['b' => 1], 'a'))->toBeFalse();
});

it('exists works with ArrayAccess', function () {
    $obj = new ArrayObject(['x' => 1]);
    expect(Arr::exists($obj, 'x'))->toBeTrue();
    expect(Arr::exists($obj, 'y'))->toBeFalse();
});

it('get returns a top-level value', function () {
    expect(Arr::get(['a' => 1], 'a'))->toBe(1);
});

it('get returns null key — the whole array', function () {
    $arr = ['a' => 1];
    expect(Arr::get($arr, null))->toBe($arr);
});

it('get returns default when key is missing', function () {
    expect(Arr::get(['a' => 1], 'b', 'default'))->toBe('default');
});

it('get returns default for non-accessible value', function () {
    expect(Arr::get('not-an-array', 'key', 'fallback'))->toBe('fallback');
});

it('get invokes closure default', function () {
    expect(Arr::get([], 'missing', fn() => 'lazy'))->toBe('lazy');
});
