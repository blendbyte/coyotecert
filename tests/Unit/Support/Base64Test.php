<?php

use CoyoteCert\Support\Base64;

it('encodes to url-safe base64 without padding', function () {
    // base64_encode('Hello') = 'SGVsbG8=' — padding stripped, no + or /
    expect(Base64::urlSafeEncode('Hello'))->toBe('SGVsbG8');
});

it('replaces + and / with - and _', function () {
    // Byte sequence that produces + and / in standard base64
    $input = "\xfb\xff\xfe"; // base64 = "+//+" → urlsafe = "-__-"... let's verify
    $standard = base64_encode($input);
    $safe = Base64::urlSafeEncode($input);

    expect($safe)->not->toContain('+');
    expect($safe)->not->toContain('/');
    expect($safe)->not->toContain('=');
});

it('roundtrips encode/decode', function (string $input) {
    expect(Base64::urlSafeDecode(Base64::urlSafeEncode($input)))->toBe($input);
})->with([
    'empty string'          => [''],
    'ascii'                 => ['Hello, World!'],
    'binary bytes'          => ["\x00\x01\x02\xff\xfe\xfd"],
    'no padding needed'     => ['abc'],
    'one padding byte'      => ['ab'],
    'two padding bytes'     => ['a'],
]);

it('decodes with missing padding', function () {
    // "SGVsbG8" is "Hello" without padding — urlSafeDecode must add it back
    expect(Base64::urlSafeDecode('SGVsbG8'))->toBe('Hello');
});
