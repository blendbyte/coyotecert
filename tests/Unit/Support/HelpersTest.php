<?php

it('value returns scalars unchanged', function () {
    expect(value(42))->toBe(42);
    expect(value('hello'))->toBe('hello');
    expect(value(null))->toBeNull();
    expect(value(true))->toBeTrue();
});

it('value invokes a Closure and returns its result', function () {
    expect(value(fn() => 'computed'))->toBe('computed');
    expect(value(fn() => 99))->toBe(99);
});

it('value does not invoke non-Closure callables', function () {
    $callable = 'strlen';
    expect(value($callable))->toBe('strlen');
});
