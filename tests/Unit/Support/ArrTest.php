<?php

declare(strict_types=1);

use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Support\Arr;

it('string() returns a present string', function () {
    expect(Arr::string(['status' => 'valid'], 'status'))->toBe('valid');
});

it('string() throws a clear AcmeException when the key is missing or not a string', function (array $data) {
    expect(fn() => Arr::string($data, 'status'))
        ->toThrow(AcmeException::class, '"status" is missing or not a string');
})->with([
    'missing' => [[]],
    'null'    => [['status' => null]],
    'int'     => [['status' => 1]],
    'array'   => [['status' => ['valid']]],
]);

it('stringOrNull() returns null for missing or non-string values', function () {
    expect(Arr::stringOrNull(['a' => 'x'], 'a'))->toBe('x');
    expect(Arr::stringOrNull([], 'a'))->toBeNull();
    expect(Arr::stringOrNull(['a' => 5], 'a'))->toBeNull();
});

it('array() returns the array or an empty one', function () {
    expect(Arr::array(['a' => ['x' => 1]], 'a'))->toBe(['x' => 1]);
    expect(Arr::array(['a' => 'x'], 'a'))->toBe([]);
    expect(Arr::array([], 'a'))->toBe([]);
});

it('strings() keeps only the string entries of a list', function () {
    expect(Arr::strings(['a' => ['x', 1, null, 'y']], 'a'))->toBe(['x', 'y']);
    expect(Arr::strings(['a' => 'x'], 'a'))->toBe([]);
});

it('arrays() keeps only the array entries of a list', function () {
    expect(Arr::arrays(['a' => [['t' => 1], 'x', ['t' => 2]]], 'a'))->toBe([['t' => 1], ['t' => 2]]);
});
