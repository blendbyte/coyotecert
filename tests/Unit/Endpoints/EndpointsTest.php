<?php

declare(strict_types=1);

use CoyoteCert\Api;
use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\CertificateBundleData;
use CoyoteCert\DTO\DomainValidationData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\AuthException;
use CoyoteCert\Exceptions\RateLimitException;
use CoyoteCert\Http\Response;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Provider\CustomProvider;
use CoyoteCert\Storage\InMemoryStorage;
use CoyoteCert\Support\Base64;

// ── Mock helpers ──────────────────────────────────────────────────────────────

function endpointMock(
    array|string $getBody = [],
    int $getCode = 200,
    array|string $postBody = [],
    int $postCode = 200,
    array $headHeaders = ['replay-nonce' => 'nonce123'],
): HttpClientInterface {
    return new class ($getCode, $getBody, $postCode, $postBody, $headHeaders) implements HttpClientInterface {
        public function __construct(
            private int $getCode,
            private array|string $getBody,
            private int $postCode,
            private array|string $postBody,
            private array $headHeaders,
        ) {}
        public function head(string $url): Response
        {
            return new Response($this->headHeaders, $url, 200, '');
        }
        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, $this->getCode, $this->getBody);
        }
        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, $this->postCode, $this->postBody);
        }
    };
}

function directoryBody(bool $withRenewalInfo = false): array
{
    $body = [
        'newNonce'   => 'https://acme.example/new-nonce',
        'newAccount' => 'https://acme.example/new-account',
        'newOrder'   => 'https://acme.example/new-order',
        'revokeCert' => 'https://acme.example/revoke',
    ];
    if ($withRenewalInfo) {
        $body['renewalInfo'] = 'https://acme.example/ari/';
    }

    return $body;
}

function testProvider(): CustomProvider
{
    return new CustomProvider(directoryUrl: 'https://acme.example/directory');
}

function makeEndpointApi(HttpClientInterface $httpClient, ?InMemoryStorage $storage = null): Api
{
    return new Api(
        provider: testProvider(),
        storage: $storage ?? new InMemoryStorage(),
        httpClient: $httpClient,
    );
}

// ── Directory ─────────────────────────────────────────────────────────────────

it('Directory::all() throws on a 503 response', function () {
    $api = makeEndpointApi(endpointMock(getBody: ['detail' => 'Service Unavailable'], getCode: 503));

    expect(fn() => $api->directory()->all())
        ->toThrow(AcmeException::class, 'Cannot get directory');
});

it('Directory::renewalInfo() returns null when renewalInfo is absent', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody(withRenewalInfo: false)));

    expect($api->directory()->renewalInfo())->toBeNull();
});

it('Directory::renewalInfo() returns the URL when renewalInfo is present', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody(withRenewalInfo: true)));

    expect($api->directory()->renewalInfo())->toBe('https://acme.example/ari/');
});

// ── Account ───────────────────────────────────────────────────────────────────

it('Account::get() throws when storage has no keys', function () {
    $storage = new InMemoryStorage(); // no keys saved
    $api     = makeEndpointApi(endpointMock(getBody: directoryBody()), $storage);

    expect(fn() => $api->account()->get())
        ->toThrow(AcmeException::class, 'Local account keys not found');
});

it('Account::create() throws via throwError on a non-201 response', function () {
    $storage = new InMemoryStorage(); // empty: create() generates the key

    // GET returns the directory body; POST returns a 500 error
    $api = makeEndpointApi(
        endpointMock(
            getBody: directoryBody(),
            getCode: 200,
            postBody: ['detail' => 'Internal Server Error'],
            postCode: 500,
        ),
        $storage,
    );

    expect(fn() => $api->account()->create('test@example.com'))
        ->toThrow(AcmeException::class);
});

// ── RenewalInfo ───────────────────────────────────────────────────────────────

it('RenewalInfo::get() returns null when renewalInfo is absent from the directory', function () {
    $storage = new InMemoryStorage();
    $storage->saveAccountKey(testProvider()->getSlug(), rsaKeyPem(), KeyType::RSA_2048);

    $api = makeEndpointApi(endpointMock(getBody: directoryBody(withRenewalInfo: false)), $storage);

    // certPem is irrelevant, the null path is hit before certId() runs
    expect($api->renewalInfo()->get('cert'))->toBeNull();
});

// ── Order ─────────────────────────────────────────────────────────────────────

it('Order::finalize() throws when the order is not ready (status=pending)', function () {
    $storage = new InMemoryStorage();
    $storage->saveAccountKey(testProvider()->getSlug(), rsaKeyPem(), KeyType::RSA_2048);

    // No HTTP calls are made; the isReady() guard short-circuits before any I/O.
    $api = makeEndpointApi(endpointMock(), $storage);

    $orderData = new OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: null,
    );

    expect(fn() => $api->order()->finalize($orderData, 'fake-csr'))
        ->toThrow(AcmeException::class, 'Cannot finalize order 1: status is pending.');
});

// ── Additional helpers ────────────────────────────────────────────────────────

/**
 * InMemoryStorage pre-seeded with an RSA-2048 account key.
 * Required by any test that calls createKeyId() (needs getPrivateKey()).
 */
function withKeyStorage(): InMemoryStorage
{
    $storage = new InMemoryStorage();
    $storage->saveAccountKey(testProvider()->getSlug(), rsaKeyPem(), KeyType::RSA_2048);

    return $storage;
}

/**
 * A flexible mock whose GET and POST behaviour is driven by closures,
 * allowing URL-based dispatch without a complex hand-rolled stub.
 */
function closureMock(
    ?callable $getHandler = null,
    ?callable $postHandler = null,
    array     $headHeaders = ['replay-nonce' => 'nonce123'],
): HttpClientInterface {
    $getH  = $getHandler  ?? static fn($url) => new Response([], $url, 200, []);
    $postH = $postHandler ?? static fn($url) => new Response([], $url, 200, []);

    return new class ($getH, $postH, $headHeaders) implements HttpClientInterface {
        public function __construct(
            private $get,
            private $post,
            private array $headHeaders,
        ) {}

        public function head(string $url): Response
        {
            return new Response($this->headHeaders, $url, 200, '');
        }

        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            return ($this->get)($url);
        }

        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            return ($this->post)($url, $payload);
        }
    };
}

/** Standard order body array. */
function orderBody(string $status = 'pending', ?string $certUrl = null): array
{
    $body = [
        'status'         => $status,
        'expires'        => '2099-01-01T00:00:00Z',
        'identifiers'    => [['type' => 'dns', 'value' => 'example.com']],
        'authorizations' => [],
        'finalize'       => 'https://acme.example/finalize/1',
    ];
    if ($certUrl !== null) {
        $body['certificate'] = $certUrl;
    }

    return $body;
}

/** Standard account body array. */
function accountBody(): array
{
    return [
        'key'       => [],
        'status'    => 'valid',
        'agreement' => '',
        'createdAt' => null,
    ];
}

/** AccountData object for use in endpoint tests. */
function makeAccountData(): AccountData
{
    return new AccountData(
        id: '1',
        url: 'https://acme.example/account/1',
        key: [],
        status: 'valid',
        agreement: '',
        createdAt: null,
    );
}

/** Pending OrderData. */
function pendingOrderData(): OrderData
{
    return new OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: null,
    );
}

/** Ready OrderData (status=ready, required for finalize). */
function readyOrderData(): OrderData
{
    return new OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'ready',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: null,
    );
}

/** OrderData with specific authorisation URLs (for allChallengesPassed tests). */
function orderDataWithAuthzUrls(array $urls): OrderData
{
    return new OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: $urls,
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: null,
    );
}

// ── Account ───────────────────────────────────────────────────────────────────

it('Account::get() succeeds when storage has a key and server returns 200', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response(
            ['location' => 'https://acme.example/account/1'],
            $url,
            200,
            accountBody(),
        ),
    );

    $account = makeEndpointApi($mock, $storage)->account()->get();

    expect($account->url)->toBe('https://acme.example/account/1');
    expect($account->status)->toBe('valid');
});

it('Account::get() throws via throwError when server returns non-200', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response([], $url, 403, ['detail' => 'Forbidden']),
    );

    expect(fn() => makeEndpointApi($mock, $storage)->account()->get())
        ->toThrow(AcmeException::class, 'Forbidden');
});

it('Account::create() throws when EAB is required but provider returns null credentials', function () {
    // ZeroSSL with no credentials: isEabRequired()=true, getEabCredentials()=null
    $api = new Api(
        provider: new \CoyoteCert\Provider\ZeroSSL(),
        storage: new InMemoryStorage(),
        httpClient: endpointMock(getBody: directoryBody()),
    );

    expect(fn() => $api->account()->create('test@example.com'))
        ->toThrow(AcmeException::class, 'requires EAB credentials');
});

it('Account::create() succeeds with valid EAB credentials', function () {
    $api = new Api(
        provider: new CustomProvider(
            directoryUrl: 'https://acme.example/directory',
            eabKid: 'kid1',
            eabHmac: 'c2VjcmV0', // base64url('secret')
        ),
        storage: new InMemoryStorage(),
        httpClient: closureMock(
            getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
            postHandler: fn($url) => new Response(
                ['location' => 'https://acme.example/account/1'],
                $url,
                201,
                accountBody(),
            ),
        ),
    );

    $account = $api->account()->create('test@example.com');
    expect($account->url)->toBe('https://acme.example/account/1');
});

it('Account::create() does not persist a new key when registration fails', function () {
    $storage = new InMemoryStorage();
    $api     = makeEndpointApi(endpointMock(getBody: directoryBody(), postBody: ['detail' => 'Boom'], postCode: 500), $storage);

    expect(fn() => $api->account()->create())->toThrow(AcmeException::class, 'Boom');
    expect($storage->hasAccountKey(testProvider()->getSlug()))->toBeFalse();
});

it('Account::create() persists the new key once the CA accepts it', function () {
    $storage = new InMemoryStorage();
    $api     = makeEndpointApi(closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response(['location' => 'https://acme.example/account/1'], $url, 201, accountBody()),
    ), $storage);

    $api->account()->create();

    expect($storage->hasAccountKey(testProvider()->getSlug()))->toBeTrue();
});

it('Account::create() registers an already stored key instead of replacing it', function () {
    $storage = withKeyStorage();
    $key     = $storage->getAccountKey(testProvider()->getSlug());
    $api     = makeEndpointApi(closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response(['location' => 'https://acme.example/account/1'], $url, 201, accountBody()),
    ), $storage);

    $api->account()->create();

    expect($storage->getAccountKey(testProvider()->getSlug()))->toBe($key);
});

it('Account::get() throws AccountNotFoundException when the CA does not know the key', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['type' => 'urn:ietf:params:acme:error:accountDoesNotExist', 'detail' => 'No account'],
        postCode: 400,
    ), withKeyStorage());

    expect(fn() => $api->account()->get())->toThrow(\CoyoteCert\Exceptions\AccountNotFoundException::class, 'No account');
});

it('CoyoteCert registers a stored key the CA does not know instead of failing', function () {
    $storage = withKeyStorage();
    $key     = $storage->getAccountKey(testProvider()->getSlug());
    $api     = makeEndpointApi(closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url, $jws) {
            $payload = json_decode(Base64::urlSafeDecode($jws['payload']), true);

            return isset($payload['onlyReturnExisting'])
                ? new Response([], $url, 400, ['type' => 'urn:ietf:params:acme:error:accountDoesNotExist'])
                : new Response(['location' => 'https://acme.example/account/1'], $url, 201, accountBody());
        },
    ), $storage);

    $method  = new \ReflectionMethod(\CoyoteCert\CoyoteCert::class, 'getOrCreateAccount');
    $account = $method->invoke(\CoyoteCert\CoyoteCert::with(testProvider()), $api);

    expect($account->url)->toBe('https://acme.example/account/1');
    expect($storage->getAccountKey(testProvider()->getSlug()))->toBe($key);
});

it('Account::create() succeeds without EAB when server returns 201 with location header', function () {
    // Non-EAB provider (Pebble) covers the non-EAB create() success path
    $api = new Api(
        provider: new \CoyoteCert\Provider\Pebble(),
        storage: new InMemoryStorage(),
        httpClient: closureMock(
            getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
            postHandler: fn($url) => new Response(
                ['location' => 'https://acme.example/account/1'],
                $url,
                201,
                accountBody(),
            ),
        ),
    );

    $account = $api->account()->create('test@example.com');
    expect($account->url)->toBe('https://acme.example/account/1');
});

// ── Order ─────────────────────────────────────────────────────────────────────

it('Order::new() throws for domains with multiple wildcards', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), new InMemoryStorage());

    expect(fn() => $api->order()->new(makeAccountData(), ['*.*.example.com']))
        ->toThrow(AcmeException::class, 'multiple wildcards');
});

it('Order::new() throws when response is not 201', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Bad Request'],
        postCode: 400,
    ), withKeyStorage());

    expect(fn() => $api->order()->new(makeAccountData(), ['example.com']))
        ->toThrow(AcmeException::class, 'Bad Request');
});

it('Order::new() returns OrderData on 201 response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: orderBody('pending'),
        postCode: 201,
    ), withKeyStorage());

    $order = $api->order()->new(makeAccountData(), ['example.com']);
    expect($order->status)->toBe('pending');
    expect($order->identifiers)->toBe([['type' => 'dns', 'value' => 'example.com']]);
});

it('Order::new() includes profile in payload when provider supports profiles', function () {
    $api = new Api(
        provider: new CustomProvider(
            directoryUrl: 'https://acme.example/directory',
            profilesSupported: true,
        ),
        storage: withKeyStorage(),
        httpClient: endpointMock(
            getBody: directoryBody(),
            postBody: orderBody('pending'),
            postCode: 201,
        ),
    );

    $order = $api->order()->new(makeAccountData(), ['example.com'], 'shortlived');
    expect($order)->toBeInstanceOf(OrderData::class);
});

it('Order::refresh() returns updated OrderData', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: orderBody('ready'),
        postCode: 200,
    ), withKeyStorage());

    $refreshed = $api->order()->refresh(pendingOrderData());
    expect($refreshed->status)->toBe('ready');
});

it('Order::waitUntilValid() returns OrderData when status becomes valid', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: orderBody('valid'),
        postCode: 200,
    ), withKeyStorage());

    $valid = $api->order()->waitUntilValid(pendingOrderData(), 1, 0);
    expect($valid->status)->toBe('valid');
});

it('Order::waitUntilValid() throws when order becomes invalid', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: orderBody('invalid'),
        postCode: 200,
    ), withKeyStorage());

    expect(fn() => $api->order()->waitUntilValid(pendingOrderData(), 1, 0))
        ->toThrow(AcmeException::class, 'invalid');
});

it('Order::waitUntilValid() throws after exhausting max attempts', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: orderBody('processing'),
        postCode: 200,
    ), withKeyStorage());

    expect(fn() => $api->order()->waitUntilValid(pendingOrderData(), 1, 0))
        ->toThrow(AcmeException::class, 'did not become valid');
});

/** Captures the decoded JWS payload of every POST. */
function payloadCapturingApi(array &$payloads, array $postBody = []): Api
{
    return makeEndpointApi(closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url, $jws) use (&$payloads, $postBody) {
            $payloads[$url] = json_decode(Base64::urlSafeDecode($jws['payload']), true);

            return str_contains($url, 'new-account')
                ? new Response(['location' => 'https://acme.example/account/1'], $url, 200, accountBody())
                : new Response([], $url, 200, $postBody);
        },
    ), withKeyStorage());
}

it('Order::finalize() sends a base64-encoded DER CSR as base64url', function () {
    $payloads = [];
    payloadCapturingApi($payloads, orderBody('valid'))->order()->finalize(readyOrderData(), base64_encode('fake-csr'));

    expect($payloads['https://acme.example/finalize/1'])->toBe(['csr' => Base64::urlSafeEncode('fake-csr')]);
});

it('Order::finalize() throws on non-200 response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Forbidden'],
        postCode: 403,
    ), withKeyStorage());

    expect(fn() => $api->order()->finalize(readyOrderData(), base64_encode('fake-csr')))
        ->toThrow(AcmeException::class);
});

it('Order::finalize() extracts base64 from a PEM-formatted CSR', function () {
    // Generate a real PEM CSR so the regex extraction path is covered.
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $csr = openssl_csr_new(['commonName' => 'example.com'], $key);
    openssl_csr_export($csr, $csrPem);

    $payloads = [];
    payloadCapturingApi($payloads, orderBody('valid'))->order()->finalize(readyOrderData(), $csrPem);

    preg_match('~-----BEGIN CERTIFICATE REQUEST-----(.*)-----END CERTIFICATE REQUEST-----~s', $csrPem, $m);
    expect($payloads['https://acme.example/finalize/1']['csr'])->toBe(Base64::urlSafeEncode(base64_decode($m[1])));
});

it('Order::new() throws RateLimitException on 429', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Too many certificates already issued'],
        postCode: 429,
    ), withKeyStorage());

    expect(fn() => $api->order()->new(makeAccountData(), ['example.com']))
        ->toThrow(RateLimitException::class, 'Too many certificates already issued');
});

it('Order::new() attaches RFC 8555 §6.7 subproblems to the thrown exception', function () {
    $subproblems = [
        [
            'type'       => 'urn:ietf:params:acme:error:rejectedIdentifier',
            'detail'     => 'This CA will not issue for "bad.example.com"',
            'identifier' => ['type' => 'dns', 'value' => 'bad.example.com'],
        ],
    ];

    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Some identifiers were rejected', 'subproblems' => $subproblems],
        postCode: 400,
    ), withKeyStorage());

    $caught = null;
    try {
        $api->order()->new(makeAccountData(), ['example.com', 'bad.example.com']);
    } catch (AcmeException $e) {
        $caught = $e;
    }

    expect($caught)->toBeInstanceOf(AcmeException::class);
    expect($caught->getSubproblems())->toBe($subproblems);
});

// ── DomainValidation ──────────────────────────────────────────────────────────

it('DomainValidation::status() throws on a non-200 authorization response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Forbidden'],
        postCode: 403,
    ), withKeyStorage());

    $order = orderDataWithAuthzUrls(['https://acme.example/authz/1']);

    expect(fn() => $api->domainValidation()->status($order))->toThrow(AuthException::class, 'Forbidden');
});

it('DomainValidation::allChallengesPassed() throws instead of passing when an authorization cannot be fetched', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Internal error'],
        postCode: 500,
    ), withKeyStorage());

    $order = orderDataWithAuthzUrls(['https://acme.example/authz/1']);

    expect(fn() => $api->domainValidation()->allChallengesPassed($order))
        ->toThrow(AcmeException::class, 'Internal error');
});

it('DomainValidation::getValidationData() builds HTTP validation item', function () {
    $storage = withKeyStorage();
    $api     = makeEndpointApi(endpointMock(), $storage);

    $challenge = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: ['type' => 'http-01', 'token' => 'abc123', 'url' => 'https://acme.example/ch/1'],
        dns: [],
        validationRecord: [],
    );

    $data = $api->domainValidation()->getValidationData([$challenge], AuthorizationChallengeEnum::HTTP);

    expect($data)->toHaveCount(1);
    expect($data[0])->toBeInstanceOf(\CoyoteCert\DTO\Http01ValidationData::class);
    expect($data[0]->filename)->toBe('abc123');
    expect($data[0]->identifier)->toBe('example.com');
});

it('DomainValidation::getValidationData() builds DNS validation item', function () {
    $storage = withKeyStorage();
    $api     = makeEndpointApi(endpointMock(), $storage);

    $challenge = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: [],
        dns: ['type' => 'dns-01', 'token' => 'dns-tok', 'url' => 'https://acme.example/ch/2'],
        validationRecord: [],
    );

    $data = $api->domainValidation()->getValidationData([$challenge], AuthorizationChallengeEnum::DNS);

    expect($data)->toHaveCount(1);
    expect($data[0])->toBeInstanceOf(\CoyoteCert\DTO\Dns01ValidationData::class);
    expect($data[0]->name)->toBe('_acme-challenge');
    expect($data[0]->identifier)->toBe('example.com');
});

it('DomainValidation::getValidationData() builds TLS-ALPN validation item', function () {
    $storage = withKeyStorage();
    $api     = makeEndpointApi(endpointMock(), $storage);

    $challenge = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: [],
        dns: [],
        validationRecord: [],
        tlsAlpn: ['type' => 'tls-alpn-01', 'token' => 'tls-tok', 'url' => 'https://acme.example/ch/4'],
    );

    $data = $api->domainValidation()->getValidationData([$challenge], AuthorizationChallengeEnum::TLS_ALPN);

    expect($data)->toHaveCount(1);
    expect($data[0])->toBeInstanceOf(\CoyoteCert\DTO\TlsAlpn01ValidationData::class);
    expect($data[0]->token)->toBe('tls-tok');
    expect($data[0]->identifier)->toBe('example.com');
});

it('DomainValidation::getValidationData() with null challenge type returns matching types', function () {
    $storage = withKeyStorage();
    $api     = makeEndpointApi(endpointMock(), $storage);

    $challenge = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: ['type' => 'http-01', 'token' => 'http-tok', 'url' => 'https://acme.example/ch/1'],
        dns: ['type' => 'dns-01',  'token' => 'dns-tok',  'url' => 'https://acme.example/ch/2'],
        validationRecord: [],
    );

    // null = all types; should return both HTTP and DNS items
    $data = $api->domainValidation()->getValidationData([$challenge], null);
    expect($data)->toHaveCount(2);
});

it('DomainValidation::start() sends HTTP challenge with localTest=false', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: [],
        postCode: 200,
    ), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: ['type' => 'http-01', 'token' => 'tok', 'url' => 'https://acme.example/ch/1'],
        dns: [],
        validationRecord: [],
    );

    $response = $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::HTTP, false);
    expect($response->getHttpResponseCode())->toBe(200);
});

it('DomainValidation::start() sends DNS challenge with localTest=false', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: [],
        postCode: 200,
    ), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: [],
        dns: ['type' => 'dns-01', 'token' => 'tok', 'url' => 'https://acme.example/ch/2'],
        validationRecord: [],
    );

    $response = $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::DNS, false);
    expect($response->getHttpResponseCode())->toBe(200);
});

it('DomainValidation::start() with localTest=true passes HTTP local check when body matches', function () {
    $storage    = withKeyStorage();
    $thumbprint = \CoyoteCert\Support\JsonWebKey::thumbprint(\CoyoteCert\Support\JsonWebKey::compute($storage->getAccountKey(testProvider()->getSlug())));
    $token      = 'local-test-token';
    $keyAuth    = $token . '.' . $thumbprint;

    $mock = closureMock(
        getHandler: fn($url) => str_contains($url, 'directory')
            ? new Response([], $url, 200, directoryBody())
            : new Response([], $url, 200, $keyAuth),
        postHandler: fn($url) => new Response([], $url, 200, []),
    );

    $dvd = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: ['type' => 'http-01', 'token' => $token, 'url' => 'https://acme.example/ch/1'],
        dns: [],
        validationRecord: [],
    );

    $response = makeEndpointApi($mock, $storage)->domainValidation()
        ->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::HTTP, true);

    expect($response->getHttpResponseCode())->toBe(200);
});

it('DomainValidation::start() throws DomainValidationException when challenge data is empty', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: [],
        dns: [],  // empty: no DNS challenge available
        validationRecord: [],
    );

    expect(fn() => $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::DNS, false))
        ->toThrow(\CoyoteCert\Exceptions\DomainValidationException::class, 'No dns-01 challenge found');
});

it('DomainValidation::start() throws when challenge POST returns >= 400', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Bad challenge'],
        postCode: 400,
    ), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier: ['type' => 'dns', 'value' => 'example.com'],
        status: 'pending',
        expires: '2099-01-01T00:00:00Z',
        file: ['type' => 'http-01', 'token' => 'tok', 'url' => 'https://acme.example/ch/1'],
        dns: [],
        validationRecord: [],
    );

    expect(fn() => $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::HTTP, false))
        ->toThrow(AcmeException::class, 'Bad challenge');
});

it('DomainValidation::allChallengesPassed() returns true immediately when no authz URLs', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    // Empty domainValidationUrls → status() returns [] (falsy) → loop never executes
    expect($api->domainValidation()->allChallengesPassed(orderDataWithAuthzUrls([])))->toBeTrue();
});

it('DomainValidation::allChallengesPassed() returns true when all challenges are valid on first try', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: [
            'identifier' => ['type' => 'dns', 'value' => 'example.com'],
            'status'     => 'valid',
            'expires'    => '2099-01-01T00:00:00Z',
            'challenges' => [],
        ],
        postCode: 200,
    ), withKeyStorage());

    expect($api->domainValidation()->allChallengesPassed(orderDataWithAuthzUrls(['https://acme.example/authz/1'])))->toBeTrue();
});

it('DomainValidation::allChallengesPassed() retries then returns true when challenge becomes valid', function () {
    $storage   = withKeyStorage();
    $callCount = 0;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use (&$callCount) {
            $callCount++;
            $status = $callCount <= 1 ? 'pending' : 'valid';

            return new Response([], $url, 200, [
                'identifier' => ['type' => 'dns', 'value' => 'example.com'],
                'status'     => $status,
                'expires'    => '2099-01-01T00:00:00Z',
                'challenges' => [],
            ]);
        },
    );

    // sleep() is a no-op in tests (see Pest.php namespace override).
    expect(makeEndpointApi($mock, $storage)->domainValidation()->allChallengesPassed(
        orderDataWithAuthzUrls(['https://acme.example/authz/1']),
    ))->toBeTrue();
});

it('DomainValidation::allChallengesPassed() returns false after 4 consecutive failures', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: [
            'identifier' => ['type' => 'dns', 'value' => 'example.com'],
            'status'     => 'pending',
            'expires'    => '2099-01-01T00:00:00Z',
            'challenges' => [],
        ],
        postCode: 200,
    ), withKeyStorage());

    // sleep() is a no-op; 4 pending iterations → return false.
    expect($api->domainValidation()->allChallengesPassed(
        orderDataWithAuthzUrls(['https://acme.example/authz/1']),
    ))->toBeFalse();
});

// ── Certificate ───────────────────────────────────────────────────────────────

it('Certificate::getBundle() returns CertificateBundleData on 200', function () {
    $certPem = "-----BEGIN CERTIFICATE-----\nMIIBtest==\n-----END CERTIFICATE-----\n";

    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: $certPem,
        postCode: 200,
    ), withKeyStorage());

    $order = new OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'valid',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: 'https://acme.example/cert/1',
    );

    $bundle = $api->certificate()->getBundle($order);
    expect($bundle->certificate)->toContain('-----BEGIN CERTIFICATE-----');
});

it('Certificate::getBundle() throws on non-200 response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Not Found'],
        postCode: 404,
    ), withKeyStorage());

    $order = new OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'valid',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: 'https://acme.example/cert/1',
    );

    expect(fn() => $api->certificate()->getBundle($order))
        ->toThrow(AcmeException::class, 'Failed to fetch certificate');
});

it('Certificate::revoke() throws when PEM is invalid (no header)', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    expect(fn() => $api->certificate()->revoke('not-a-valid-cert'))
        ->toThrow(AcmeException::class, 'Could not parse the certificate');
});

it('Certificate::revoke() throws when PEM header is present but body is not a valid certificate', function () {
    // Contains the required header so the str_contains guard passes,
    // but the body is garbage so openssl_x509_read() returns false (line 36).
    $api     = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());
    $fakePem = "-----BEGIN CERTIFICATE-----\nnot-valid-base64!!!\n-----END CERTIFICATE-----";

    expect(fn() => $api->certificate()->revoke($fakePem))
        ->toThrow(AcmeException::class, 'Could not parse the certificate');
});

it('Certificate::revoke() sends the DER certificate as base64url with the reason code', function () {
    $key  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $cert = openssl_csr_sign(openssl_csr_new(['commonName' => 'example.com'], $key), null, $key, 365);
    openssl_x509_export($cert, $certPem);

    $payloads = [];
    payloadCapturingApi($payloads)->certificate()->revoke($certPem, \CoyoteCert\Enums\RevocationReason::Superseded);

    preg_match('~-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----~s', $certPem, $m);
    expect($payloads['https://acme.example/revoke'])->toBe([
        'certificate' => Base64::urlSafeEncode(base64_decode($m[1])),
        'reason'      => 4,
    ]);
});

it('Certificate::revoke() throws AcmeException when server rejects revocation', function () {
    $storage = withKeyStorage();
    $key     = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $csr     = openssl_csr_new(['commonName' => 'test.example.com'], $key);
    $cert    = openssl_csr_sign($csr, null, $key, 365);
    openssl_x509_export($cert, $certPem);

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => str_contains($url, 'account')
            ? new Response(['location' => 'https://acme.example/account/1'], $url, 200, accountBody())
            : new Response([], $url, 403, ['detail' => 'Forbidden']),
    );

    expect(fn() => makeEndpointApi($mock, $storage)->certificate()->revoke($certPem))
        ->toThrow(AcmeException::class);
});

// ── RenewalInfo ───────────────────────────────────────────────────────────────

it('RenewalInfo::get() returns a RenewalWindow when server responds 200', function () {
    $storage   = withKeyStorage();
    [$leafPem] = caSignedLeaf();

    $renewalBody = [
        'suggestedWindow' => [
            'start' => '2026-04-01T00:00:00Z',
            'end'   => '2026-04-15T00:00:00Z',
        ],
        'explanationURL' => 'https://acme.example/why',
    ];

    $mock = closureMock(
        getHandler: fn($url) => str_contains($url, 'ari/')
            ? new Response([], $url, 200, $renewalBody)
            : new Response([], $url, 200, directoryBody(withRenewalInfo: true)),
    );

    $window = makeEndpointApi($mock, $storage)->renewalInfo()->get($leafPem);

    expect($window)->not->toBeNull();
    expect($window->explanationUrl)->toBe('https://acme.example/why');
});

it('RenewalInfo::get() returns null when ARI endpoint returns non-200', function () {
    $storage   = withKeyStorage();
    [$leafPem] = caSignedLeaf();

    $mock = closureMock(
        getHandler: fn($url) => str_contains($url, 'ari/')
            ? new Response([], $url, 404, [])
            : new Response([], $url, 200, directoryBody(withRenewalInfo: true)),
    );

    expect(makeEndpointApi($mock, $storage)->renewalInfo()->get($leafPem))->toBeNull();
});

// ── badNonce retry ────────────────────────────────────────────────────────────

it('postSigned() retries once on badNonce and succeeds (KID path)', function () {
    $storage = withKeyStorage();
    $calls   = 0;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use (&$calls) {
            $calls++;
            if ($calls === 1) {
                return new Response([], $url, 400, [
                    'type'   => 'urn:ietf:params:acme:error:badNonce',
                    'detail' => 'JWS has an invalid anti-replay nonce',
                ]);
            }

            return new Response([], $url, 200, accountBody());
        },
    );

    $result = makeEndpointApi($mock, $storage)->account()->update(makeAccountData(), []);
    expect($result->status)->toBe('valid');
    expect($calls)->toBe(2);
});

it('postToAccountUrl() retries once on badNonce and succeeds (JWK path)', function () {
    $storage = withKeyStorage();
    $calls   = 0;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use (&$calls) {
            $calls++;
            if ($calls === 1) {
                return new Response([], $url, 400, [
                    'type'   => 'urn:ietf:params:acme:error:badNonce',
                    'detail' => 'JWS has an invalid anti-replay nonce',
                ]);
            }

            return new Response(['location' => 'https://acme.example/account/1'], $url, 200, accountBody());
        },
    );

    $result = makeEndpointApi($mock, $storage)->account()->get();
    expect($result->url)->toBe('https://acme.example/account/1');
    expect($calls)->toBe(2);
});

// ── Account::update() ─────────────────────────────────────────────────────────

it('Account::update() returns AccountData with updated contact on success', function () {
    $storage = withKeyStorage();
    $contact = ['mailto:admin@example.com'];

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response([], $url, 200, array_merge(accountBody(), ['contact' => $contact])),
    );

    $updated = makeEndpointApi($mock, $storage)->account()->update(makeAccountData(), $contact);

    expect($updated->contact)->toBe($contact);
    expect($updated->status)->toBe('valid');
});

it('Account::update() throws on non-200 response', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response([], $url, 403, ['detail' => 'Unauthorized']),
    );

    expect(fn() => makeEndpointApi($mock, $storage)->account()->update(makeAccountData(), []))
        ->toThrow(AcmeException::class, 'Unauthorized');
});

// ── Account::deactivate() ─────────────────────────────────────────────────────

it('Account::deactivate() returns account with status=deactivated on success', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response([], $url, 200, array_merge(accountBody(), ['status' => 'deactivated'])),
    );

    $updated = makeEndpointApi($mock, $storage)->account()->deactivate(makeAccountData());
    expect($updated->status)->toBe('deactivated');
});

it('Account::deactivate() throws on non-200 response', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response([], $url, 400, ['detail' => 'Bad Request']),
    );

    expect(fn() => makeEndpointApi($mock, $storage)->account()->deactivate(makeAccountData()))
        ->toThrow(AcmeException::class);
});

// ── Account::keyRollover() ────────────────────────────────────────────────────

function directoryBodyWithKeyChange(bool $withRenewalInfo = false): array
{
    return array_merge(directoryBody($withRenewalInfo), ['keyChange' => 'https://acme.example/key-change']);
}

it('Account::keyRollover() saves a new RSA key and returns AccountData on success', function () {
    $storage = withKeyStorage();
    $oldKey  = $storage->getAccountKey(testProvider()->getSlug());

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
        postHandler: fn($url) => new Response([], $url, 200, accountBody()),
    );

    $result = makeEndpointApi($mock, $storage)->account()->keyRollover(makeAccountData());

    expect($result->status)->toBe('valid');
    expect($storage->getAccountKey(testProvider()->getSlug()))->not->toBe($oldKey);
});

it('Account::keyRollover() saves a new EC key when the account key is EC', function () {
    $storage = new InMemoryStorage();
    $storage->saveAccountKey(testProvider()->getSlug(), ecKeyPem(), KeyType::EC_P256);
    $oldKey = $storage->getAccountKey(testProvider()->getSlug());

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
        postHandler: fn($url) => new Response([], $url, 200, accountBody()),
    );

    $result = makeEndpointApi($mock, $storage)->account()->keyRollover(makeAccountData());

    expect($result->status)->toBe('valid');
    expect($storage->getAccountKey(testProvider()->getSlug()))->not->toBe($oldKey);
});

it('Account::keyRollover() retries once on badNonce', function () {
    $storage = withKeyStorage();
    $calls   = 0;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
        postHandler: function ($url) use (&$calls) {
            if (!str_contains($url, 'key-change')) {
                return new Response([], $url, 200, accountBody()); // account read-back
            }

            $calls++;
            if ($calls === 1) {
                return new Response([], $url, 400, [
                    'type'   => 'urn:ietf:params:acme:error:badNonce',
                    'detail' => 'JWS has an invalid anti-replay nonce',
                ]);
            }

            return new Response([], $url, 200, '');
        },
    );

    $result = makeEndpointApi($mock, $storage)->account()->keyRollover(makeAccountData());
    expect($result->status)->toBe('valid');
    expect($calls)->toBe(2); // the key-change request is sent twice, once per nonce
});

it('Account::keyRollover() throws on non-200 response', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
        postHandler: fn($url) => new Response([], $url, 400, ['detail' => 'Key rollover failed']),
    );

    expect(fn() => makeEndpointApi($mock, $storage)->account()->keyRollover(makeAccountData()))
        ->toThrow(AcmeException::class, 'Key rollover failed');
});

// ── Directory::keyChange() ────────────────────────────────────────────────────

it('Directory::keyChange() returns the keyChange URL', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBodyWithKeyChange()));
    expect($api->directory()->keyChange())->toBe('https://acme.example/key-change');
});

// ── Order::new() with replaces ────────────────────────────────────────────────

it('Order::new() includes replaces in the JWS payload when replacesId is provided', function () {
    $storage  = withKeyStorage();
    $captured = null;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url, $payload) use (&$captured) {
            if (str_contains($url, 'new-order')) {
                $captured = $payload;
            }

            return new Response(['location' => 'https://acme.example/order/1'], $url, 201, orderBody('pending'));
        },
    );

    makeEndpointApi($mock, $storage)->order()->new(makeAccountData(), ['example.com'], '', 'hashA.serialB');

    $inner = json_decode(base64_decode(strtr($captured['payload'], '-_', '+/')), true);
    expect($inner)->toHaveKey('replaces');
    expect($inner['replaces'])->toBe('hashA.serialB');
});

it('Order::new() omits replaces from the payload when replacesId is empty', function () {
    $storage  = withKeyStorage();
    $captured = null;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url, $payload) use (&$captured) {
            if (str_contains($url, 'new-order')) {
                $captured = $payload;
            }

            return new Response(['location' => 'https://acme.example/order/1'], $url, 201, orderBody('pending'));
        },
    );

    makeEndpointApi($mock, $storage)->order()->new(makeAccountData(), ['example.com']);

    $inner = json_decode(base64_decode(strtr($captured['payload'], '-_', '+/')), true);
    expect($inner)->not->toHaveKey('replaces');
});

// ── Retry-After / exponential back-off ───────────────────────────────────────

it('Order::waitUntilValid() respects the Retry-After header and resolves to valid', function () {
    $storage   = withKeyStorage();
    $callCount = 0;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use (&$callCount) {
            $callCount++;

            // First poll: processing + Retry-After hint; second poll: valid
            return $callCount === 1
                ? new Response(['retry-after' => '3'], $url, 200, orderBody('processing'))
                : new Response([], $url, 200, orderBody('valid'));
        },
    );

    $order = makeEndpointApi($mock, $storage)->order()->waitUntilValid(pendingOrderData(), 5, 1);

    expect($order->status)->toBe('valid');
    expect($callCount)->toBe(2);
});

it('Order::waitUntilValid() uses exponential back-off when Retry-After is absent', function () {
    $storage   = withKeyStorage();
    $callCount = 0;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use (&$callCount) {
            $callCount++;

            // Two processing rounds then valid, no Retry-After header
            return $callCount < 3
                ? new Response([], $url, 200, orderBody('processing'))
                : new Response([], $url, 200, orderBody('valid'));
        },
    );

    $order = makeEndpointApi($mock, $storage)->order()->waitUntilValid(pendingOrderData(), 5, 0);

    expect($order->status)->toBe('valid');
    expect($callCount)->toBe(3);
});

it('DomainValidation::allChallengesPassed() respects the Retry-After header', function () {
    $storage   = withKeyStorage();
    $callCount = 0;

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use (&$callCount) {
            $callCount++;
            $status  = $callCount === 1 ? 'pending' : 'valid';
            $headers = $callCount === 1 ? ['retry-after' => '2'] : [];

            return new Response($headers, $url, 200, [
                'identifier' => ['type' => 'dns', 'value' => 'example.com'],
                'status'     => $status,
                'expires'    => '2099-01-01T00:00:00Z',
                'challenges' => [],
            ]);
        },
    );

    $passed = makeEndpointApi($mock, $storage)->domainValidation()->allChallengesPassed(
        orderDataWithAuthzUrls(['https://acme.example/authz/1']),
    );

    expect($passed)->toBeTrue();
    expect($callCount)->toBe(2); // pending → valid after one retry
});

// ── Certificate::getBundle() preferred chain selection ────────────────────────

function makeCertBundle(string $issuerCN = 'Test Issuer CA'): string
{
    $issuerKey  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $issuerCsr  = openssl_csr_new(['commonName' => $issuerCN], $issuerKey);
    $issuerCert = openssl_csr_sign($issuerCsr, null, $issuerKey, 3650, serial: 2);
    openssl_x509_export($issuerCert, $issuerPem);

    $leafKey  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $leafCsr  = openssl_csr_new(['commonName' => 'leaf.example.com'], $leafKey);
    $leafCert = openssl_csr_sign($leafCsr, $issuerCert, $issuerKey, 365, serial: 3);
    openssl_x509_export($leafCert, $leafPem);

    return $leafPem . "\n" . $issuerPem;
}

function certOrderData(): OrderData
{
    return new OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'valid',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: 'https://acme.example/cert/1',
    );
}

it('Certificate::getBundle() returns preferred alternate chain when issuer CN matches', function () {
    $storage         = withKeyStorage();
    $primaryBundle   = makeCertBundle('Default Root CA');
    $alternateBundle = makeCertBundle('ISRG Root X1');

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use ($primaryBundle, $alternateBundle) {
            if (str_contains($url, '/alt')) {
                return new Response([], $url, 200, $alternateBundle);
            }

            return new Response(
                ['link' => '<https://acme.example/cert/1/alt>;rel="alternate"'],
                $url,
                200,
                $primaryBundle,
            );
        },
    );

    $bundle = makeEndpointApi($mock, $storage)->certificate()->getBundle(certOrderData(), 'ISRG Root X1');

    preg_match_all('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~i', $bundle->caBundle, $m);
    $parsed = openssl_x509_parse($m[1][0]);
    expect($parsed['subject']['CN'])->toBe('ISRG Root X1');
});

it('Certificate::getBundle() falls back to primary when no alternate chain matches preferred issuer', function () {
    $storage         = withKeyStorage();
    $primaryBundle   = makeCertBundle('Default Root CA');
    $alternateBundle = makeCertBundle('Some Other CA');

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use ($primaryBundle, $alternateBundle) {
            if (str_contains($url, '/alt')) {
                return new Response([], $url, 200, $alternateBundle);
            }

            return new Response(
                ['link' => '<https://acme.example/cert/1/alt>;rel="alternate"'],
                $url,
                200,
                $primaryBundle,
            );
        },
    );

    $bundle = makeEndpointApi($mock, $storage)->certificate()->getBundle(certOrderData(), 'ISRG Root X1');

    preg_match_all('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~i', $bundle->caBundle, $m);
    $parsed = openssl_x509_parse($m[1][0]);
    expect($parsed['subject']['CN'])->toBe('Default Root CA');
});

it('Certificate::getBundle() returns primary chain when no Link header is present with preferredChain set', function () {
    $storage       = withKeyStorage();
    $primaryBundle = makeCertBundle('Default Root CA');

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response([], $url, 200, $primaryBundle),
    );

    $bundle = makeEndpointApi($mock, $storage)->certificate()->getBundle(certOrderData(), 'ISRG Root X1');

    preg_match_all('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~i', $bundle->caBundle, $m);
    $parsed = openssl_x509_parse($m[1][0]);
    expect($parsed['subject']['CN'])->toBe('Default Root CA');
});

it('Certificate::getBundle() skips alternate chains that return non-200 and falls back to primary', function () {
    $storage       = withKeyStorage();
    $primaryBundle = makeCertBundle('Default Root CA');

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use ($primaryBundle) {
            if (str_contains($url, '/alt')) {
                return new Response([], $url, 503, 'Service Unavailable');
            }

            return new Response(
                ['link' => '<https://acme.example/cert/1/alt>;rel="alternate"'],
                $url,
                200,
                $primaryBundle,
            );
        },
    );

    $bundle = makeEndpointApi($mock, $storage)->certificate()->getBundle(certOrderData(), 'ISRG Root X1');

    preg_match_all('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~i', $bundle->caBundle, $m);
    $parsed = openssl_x509_parse($m[1][0]);
    expect($parsed['subject']['CN'])->toBe('Default Root CA');
});

it('Certificate::getBundle() skips alternate chains whose caBundle is empty', function () {
    $storage        = withKeyStorage();
    $primaryBundle  = makeCertBundle('Default Root CA');
    $leafOnlyBundle = "-----BEGIN CERTIFICATE-----\nMIIBtest==\n-----END CERTIFICATE-----\n";

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use ($primaryBundle, $leafOnlyBundle) {
            if (str_contains($url, '/alt')) {
                return new Response([], $url, 200, $leafOnlyBundle);
            }

            return new Response(
                ['link' => '<https://acme.example/cert/1/alt>;rel="alternate"'],
                $url,
                200,
                $primaryBundle,
            );
        },
    );

    $bundle = makeEndpointApi($mock, $storage)->certificate()->getBundle(certOrderData(), 'ISRG Root X1');

    preg_match_all('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~i', $bundle->caBundle, $m);
    $parsed = openssl_x509_parse($m[1][0]);
    expect($parsed['subject']['CN'])->toBe('Default Root CA');
});

it('chainMatchesIssuer() returns false when caBundle has no PEM certificate blocks', function () {
    $cert   = makeEndpointApi(endpointMock(), withKeyStorage())->certificate();
    $method = new \ReflectionMethod($cert, 'chainMatchesIssuer');

    $bundle = new \CoyoteCert\DTO\CertificateBundleData(
        certificate: '',
        fullchain: '',
        caBundle: 'not-a-pem-block',
    );

    expect($method->invoke($cert, $bundle, 'ISRG Root X1'))->toBeFalse();
});

it('Certificate::getBundle() handles multiple Link headers (comma-separated) and selects matching chain', function () {
    $storage          = withKeyStorage();
    $primaryBundle    = makeCertBundle('Default Root CA');
    $alternate1Bundle = makeCertBundle('Other CA');
    $alternate2Bundle = makeCertBundle('ISRG Root X1');

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use ($primaryBundle, $alternate1Bundle, $alternate2Bundle) {
            if (str_contains($url, '/alt2')) {
                return new Response([], $url, 200, $alternate2Bundle);
            }

            if (str_contains($url, '/alt1')) {
                return new Response([], $url, 200, $alternate1Bundle);
            }

            return new Response(
                ['link' => '<https://acme.example/cert/1/alt1>;rel="alternate", <https://acme.example/cert/1/alt2>;rel="alternate"'],
                $url,
                200,
                $primaryBundle,
            );
        },
    );

    $bundle = makeEndpointApi($mock, $storage)->certificate()->getBundle(certOrderData(), 'ISRG Root X1');

    preg_match_all('~(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)~i', $bundle->caBundle, $m);
    $parsed = openssl_x509_parse($m[1][0]);
    expect($parsed['subject']['CN'])->toBe('ISRG Root X1');
});

// ── Certificate::getBundle() null certificateUrl path (line 15) ──────────────

it('Certificate::getBundle() throws AcmeException when certificateUrl is null', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    $order = new \CoyoteCert\DTO\OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'valid',
        expires: '2099-01-01T00:00:00Z',
        identifiers: [],
        domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: null,   // ← triggers the line-15 guard
    );

    expect(fn() => $api->certificate()->getBundle($order))
        ->toThrow(\CoyoteCert\Exceptions\AcmeException::class, 'does not have a certificate URL');
});

// ── RenewalInfo::certId() ─────────────────────────────────────────────────────

it('RenewalInfo::certId() encodes the AKI key identifier and the DER serial (RFC 9773 §4.1)', function () {
    // 0x87654321 has the high bit set, so DER needs a leading zero byte (RFC example: "AIdlQyE")
    [$leafPem, $issuerPem] = caSignedLeaf(0x87654321);

    $mock   = closureMock(getHandler: fn($url) => new Response([], $url, 200, directoryBody(withRenewalInfo: true)));
    $certId = makeEndpointApi($mock, withKeyStorage())->renewalInfo()->certId($leafPem);

    $ski = openssl_x509_parse($issuerPem)['extensions']['subjectKeyIdentifier'];

    expect($certId)->toBe(Base64::urlSafeEncode(hex2bin(str_replace(':', '', $ski))) . '.AIdlQyE');
});

it('RenewalInfo::certId() does not pad a serial without the high bit set', function () {
    [$leafPem] = caSignedLeaf(0x1234);

    $mock   = closureMock(getHandler: fn($url) => new Response([], $url, 200, directoryBody(withRenewalInfo: true)));
    $certId = makeEndpointApi($mock, withKeyStorage())->renewalInfo()->certId($leafPem);

    expect(explode('.', $certId)[1])->toBe(Base64::urlSafeEncode("\x12\x34"));
});

it('RenewalInfo::certId() throws CryptoException when certPem is not a valid certificate', function () {
    $mock = closureMock(getHandler: fn($url) => new Response([], $url, 200, directoryBody(withRenewalInfo: true)));

    expect(fn() => makeEndpointApi($mock, withKeyStorage())->renewalInfo()->certId('not-a-cert'))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Failed to parse certificate');
});

it('RenewalInfo::certId() throws CryptoException when the certificate has no Authority Key Identifier', function () {
    // Explicit config: the system openssl.cnf on some distros adds an AKI to self-signed certs
    $cnf = tempnam(sys_get_temp_dir(), 'cc-cnf');
    file_put_contents($cnf, "[req]\ndistinguished_name = dn\n[dn]\n[v3_plain]\nbasicConstraints = CA:FALSE\n");

    $opts = ['config' => $cnf, 'x509_extensions' => 'v3_plain', 'digest_alg' => 'sha256'];
    $key  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $cert = openssl_csr_sign(openssl_csr_new(['commonName' => 'self.example.com'], $key, $opts), null, $key, 30, $opts, 1);
    openssl_x509_export($cert, $pem);
    unlink($cnf);

    expect(openssl_x509_parse($pem)['extensions'])->not->toHaveKey('authorityKeyIdentifier');

    $mock = closureMock(getHandler: fn($url) => new Response([], $url, 200, directoryBody(withRenewalInfo: true)));

    expect(fn() => makeEndpointApi($mock, withKeyStorage())->renewalInfo()->certId($pem))
        ->toThrow(\CoyoteCert\Exceptions\CryptoException::class, 'Authority Key Identifier');
});

// ── Order robustness ──────────────────────────────────────────────────────────

function replacesRetryApi(int $code, string $type, array &$sent): Api
{
    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url, $jws) use ($code, $type, &$sent) {
            $payload = json_decode(Base64::urlSafeDecode($jws['payload']), true);
            $sent[]  = $payload;

            return isset($payload['replaces'])
                ? new Response([], $url, $code, ['type' => $type, 'detail' => 'rejected'])
                : new Response(['location' => 'https://acme.example/order/1'], $url, 201, orderBody('pending'));
        },
    );

    return makeEndpointApi($mock, withKeyStorage());
}

it('Order::new() retries without replaces when the CA reports it already replaced', function () {
    $sent = [];
    $api  = replacesRetryApi(409, 'urn:ietf:params:acme:error:alreadyReplaced', $sent);

    $order = $api->order()->new(makeAccountData(), ['example.com'], '', 'aki.serial');

    expect($order->status)->toBe('pending');
    expect($sent)->toHaveCount(2);
    expect($sent[1])->not->toHaveKey('replaces');
});

it('Order::new() does not retry without replaces for errors about the order itself', function () {
    $sent = [];
    $api  = replacesRetryApi(400, 'urn:ietf:params:acme:error:rejectedIdentifier', $sent);

    expect(fn() => $api->order()->new(makeAccountData(), ['example.com'], '', 'aki.serial'))
        ->toThrow(AcmeException::class, 'rejected');
    expect($sent)->toHaveCount(1);
});

it('Order::refresh() throws on an error response instead of building an OrderData from it', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['type' => 'urn:ietf:params:acme:error:serverInternal', 'detail' => 'Boom'],
        postCode: 500,
    ), withKeyStorage());

    expect(fn() => $api->order()->refresh(pendingOrderData()))->toThrow(AcmeException::class, 'Boom');
});

it('Order::waitUntilValid() throws on an error response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['detail' => 'Not found'],
        postCode: 404,
    ), withKeyStorage());

    expect(fn() => $api->order()->waitUntilValid(pendingOrderData(), 3, 0))
        ->toThrow(AcmeException::class, 'Not found');
});

it('Order::waitUntilValid() includes the order error detail when it becomes invalid', function () {
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: orderBody('invalid') + ['error' => ['detail' => 'CSR is missing a SAN']],
        postCode: 200,
    ), withKeyStorage());

    expect(fn() => $api->order()->waitUntilValid(pendingOrderData(), 1, 0))
        ->toThrow(AcmeException::class, 'CSR is missing a SAN');
});

it('OrderData::fromResponse() accepts an order without expires', function () {
    $body = orderBody('valid');
    unset($body['expires']);

    $order = OrderData::fromResponse(new Response([], 'https://acme.example/order/1', 200, $body));

    expect($order->expires)->toBeNull();
});

it('parseRetryAfterSeconds() reads delay-seconds and HTTP-dates', function () {
    $endpoint = makeEndpointApi(endpointMock())->order();
    $parse    = new \ReflectionMethod($endpoint, 'parseRetryAfterSeconds');

    $inTwoMinutes = gmdate('D, d M Y H:i:s \G\M\T', time() + 120);

    expect($parse->invoke($endpoint, new Response(['retry-after' => '30'], '', 200, '')))->toBe(30);
    expect($parse->invoke($endpoint, new Response(['retry-after' => $inTwoMinutes], '', 200, '')))->toBeBetween(118, 120);
    expect($parse->invoke($endpoint, new Response(['retry-after' => 'garbage'], '', 200, '')))->toBeNull();
    expect($parse->invoke($endpoint, new Response([], '', 200, '')))->toBeNull();
});

it('pollDelay() caps Retry-After and falls back to exponential back-off', function () {
    $endpoint = makeEndpointApi(endpointMock())->order();
    $delay    = new \ReflectionMethod($endpoint, 'pollDelay');

    expect($delay->invoke($endpoint, 86400, 0, 2))->toBe(120);
    expect($delay->invoke($endpoint, 3, 0, 2))->toBe(3);
    expect($delay->invoke($endpoint, null, 2, 2))->toBe(8);
    expect($delay->invoke($endpoint, null, 10, 2))->toBe(64);
});

it('RenewalInfo::get() ignores a window that ends before it starts', function () {
    [$leafPem] = caSignedLeaf();

    $mock = closureMock(
        getHandler: fn($url) => str_contains($url, 'ari/')
            ? new Response([], $url, 200, ['suggestedWindow' => ['start' => '2026-05-02T00:00:00Z', 'end' => '2026-05-01T00:00:00Z']])
            : new Response([], $url, 200, directoryBody(withRenewalInfo: true)),
    );

    expect(makeEndpointApi($mock, withKeyStorage())->renewalInfo()->get($leafPem))->toBeNull();
});

it('Api fetches the directory once and reuses it', function () {
    $gets = 0;
    $api  = makeEndpointApi(closureMock(getHandler: function ($url) use (&$gets) {
        $gets++;

        return new Response([], $url, 200, directoryBody());
    }));

    $api->directory()->newAccount();
    $api->directory()->newOrder();
    $api->directory()->newNonce();

    expect($gets)->toBe(1);
});

it('Nonce::getNew() throws when the CA returns no Replay-Nonce', function () {
    $api = makeEndpointApi(closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        headHeaders: [],
    ));

    expect(fn() => $api->nonce()->getNew())->toThrow(AcmeException::class, 'no Replay-Nonce');
});

it('Certificate::getBundle() asks for a PEM certificate chain', function () {
    $mock = new class implements HttpClientInterface {
        public array $headers = [];

        public function head(string $url): Response
        {
            return new Response(['replay-nonce' => 'nonce'], $url, 200, '');
        }

        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response
        {
            return new Response([], $url, 200, directoryBody());
        }

        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response
        {
            $this->headers = $headers;

            return new Response([], $url, 200, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
        }
    };

    $order = new OrderData(
        id: '1',
        url: 'https://acme.example/order/1',
        status: 'valid',
        expires: null,
        identifiers: [],
        domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl: 'https://acme.example/account/1',
        certificateUrl: 'https://acme.example/cert/1',
    );

    makeEndpointApi($mock, withKeyStorage())->certificate()->getBundle($order);

    expect($mock->headers)->toBe(['Accept: application/pem-certificate-chain']);
});

/**
 * The chain a CA serves for a leaf: $cas runs from the (unserved) root down to the
 * issuing intermediate, so the topmost served certificate is issued by $cas[0].
 */
function servedChain(string ...$cas): string
{
    $issuerKey  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $issuerCert = openssl_csr_sign(openssl_csr_new(['commonName' => $cas[0]], $issuerKey), null, $issuerKey, 30);
    $served     = [];

    foreach ([...array_slice($cas, 1), 'leaf.example.com'] as $cn) {
        $key  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $cert = openssl_csr_sign(openssl_csr_new(['commonName' => $cn], $key), $issuerCert, $issuerKey, 30);
        openssl_x509_export($cert, $pem);
        array_unshift($served, $pem);
        [$issuerKey, $issuerCert] = [$key, $cert];
    }

    return implode("\n", $served);
}

it('Certificate::getBundle() picks the chain leading to the preferred root, not one merely containing it', function () {
    // Default chain: leaf <- E7 <- ISRG Root X2. Alternate: leaf <- E7 <- X2 cross-signed by ISRG Root X1.
    // Both contain an "ISRG Root X2" name somewhere, only the default one is issued by it at the top.
    $primary   = servedChain('ISRG Root X2', 'E7');
    $alternate = servedChain('ISRG Root X1', 'ISRG Root X2', 'E7');

    $mock = closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => str_contains($url, '/alt')
            ? new Response([], $url, 200, $alternate)
            : new Response(['link' => '<https://acme.example/cert/1/alt>;rel="alternate"'], $url, 200, $primary),
    );
    $certificate = makeEndpointApi($mock, withKeyStorage())->certificate();

    expect($certificate->getBundle(certOrderData(), 'ISRG Root X2')->fullchain)->toBe(CertificateBundleData::fromResponse(new Response([], '', 200, $primary))->fullchain);
    expect($certificate->getBundle(certOrderData(), 'isrg root x1')->fullchain)->toBe(CertificateBundleData::fromResponse(new Response([], '', 200, $alternate))->fullchain);
});

it('typed exceptions carry the ACME problem type and subproblems', function (int $code, string $class) {
    $sub = [['type' => 'urn:ietf:params:acme:error:rejectedIdentifier', 'detail' => 'nope', 'identifier' => ['type' => 'dns', 'value' => 'x.test']]];
    $api = makeEndpointApi(endpointMock(
        getBody: directoryBody(),
        postBody: ['type' => 'urn:ietf:params:acme:error:example', 'detail' => 'Problem', 'subproblems' => $sub],
        postCode: $code,
    ), withKeyStorage());

    try {
        $api->order()->refresh(pendingOrderData());
        $this->fail('Expected an exception');
    } catch (AcmeException $e) {
        expect($e)->toBeInstanceOf($class);
        expect($e->getProblemType())->toBe('urn:ietf:params:acme:error:example');
        expect($e->getSubproblems())->toBe($sub);
    }
})->with([
    'generic'    => [400, AcmeException::class],
    'auth'       => [403, AuthException::class],
    'rate limit' => [429, RateLimitException::class],
]);

it('Account::create() registers the email as a mailto contact', function () {
    $sent = [];
    $api  = makeEndpointApi(closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url, $jws) use (&$sent) {
            $sent[] = json_decode(Base64::urlSafeDecode($jws['payload']), true);

            return new Response(['location' => 'https://acme.example/account/1'], $url, 201, accountBody());
        },
    ), new InMemoryStorage());

    $api->account()->create('admin@example.com');
    $api->account()->create(); // no email: no contact

    expect($sent[0]['contact'])->toBe(['mailto:admin@example.com']);
    expect($sent[1])->not->toHaveKey('contact');
});

it('Account::keyRollover() signs the inner JWS with the new key and no nonce (RFC 8555 §7.3.5)', function () {
    $outer = null;
    $api   = makeEndpointApi(closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
        postHandler: function ($url, $jws) use (&$outer) {
            if (str_contains($url, 'key-change')) {
                $outer = $jws;

                return new Response([], $url, 200, ''); // RFC 8555 §7.3.5 needs no body (Pebble sends none)
            }

            return new Response(['location' => 'https://acme.example/account/1'], $url, 200, accountBody());
        },
    ), withKeyStorage());

    $account = $api->account()->keyRollover(makeAccountData());
    expect($account->url)->toBe('https://acme.example/account/1');

    $inner          = json_decode(Base64::urlSafeDecode($outer['payload']), true);
    $innerProtected = json_decode(Base64::urlSafeDecode($inner['protected']), true);
    $innerPayload   = json_decode(Base64::urlSafeDecode($inner['payload']), true);

    expect($innerProtected)->toHaveKeys(['alg', 'jwk', 'url'])->not->toHaveKey('nonce');
    expect($innerProtected['url'])->toBe('https://acme.example/key-change');
    expect($innerPayload['account'])->toBe('https://acme.example/account/1');
    expect($innerPayload)->toHaveKey('oldKey');
});

// ── Directory meta ────────────────────────────────────────────────────────────

function metaApi(array $meta, array &$sent, ?\CoyoteCert\Provider\AcmeProviderInterface $provider = null): Api
{
    $provider ??= testProvider();
    $storage = new InMemoryStorage();
    $storage->saveAccountKey($provider->getSlug(), rsaKeyPem(), KeyType::RSA_2048);

    return new Api(
        provider: $provider,
        storage: $storage,
        httpClient: closureMock(
            getHandler: fn($url) => new Response([], $url, 200, directoryBody() + ['meta' => $meta]),
            postHandler: function ($url, $jws) use (&$sent) {
                $sent[] = json_decode(Base64::urlSafeDecode($jws['payload']), true);

                return str_contains($url, 'new-order')
                    ? new Response(['location' => 'https://acme.example/order/1'], $url, 201, orderBody('pending'))
                    : new Response(['location' => 'https://acme.example/account/1'], $url, 201, accountBody());
            },
        ),
    );
}

it('Order::new() rejects a profile the directory does not list', function () {
    $sent = [];
    $api  = metaApi(['profiles' => ['classic' => 'x', 'shortlived' => 'y']], $sent);

    expect(fn() => $api->order()->new(makeAccountData(), ['example.com'], 'tlsserver'))
        ->toThrow(AcmeException::class, 'does not offer the "tlsserver" profile. Available: classic, shortlived');
    expect($sent)->toBe([]);
});

it('Order::new() sends a listed profile even when the provider class does not claim profile support', function () {
    $sent = [];
    $api  = metaApi(['profiles' => ['minimal' => 'x']], $sent, new \CoyoteCert\Provider\GoogleTrustServices('kid', 'hmac'));

    $api->order()->new(makeAccountData(), ['example.com'], 'minimal');

    expect($sent[0]['profile'])->toBe('minimal');
});

it('Order::new() rejects a profile when the CA supports none instead of dropping it', function () {
    $sent = [];
    $api  = metaApi([], $sent);

    expect(fn() => $api->order()->new(makeAccountData(), ['example.com'], 'shortlived'))
        ->toThrow(AcmeException::class, 'does not support ACME profiles');
});

it('Account::create() follows the directory: no EAB error when it is not required', function () {
    $sent = [];
    $api  = metaApi(['externalAccountRequired' => false], $sent, new \CoyoteCert\Provider\SslCom());

    $api->account()->create();

    expect($sent[0])->not->toHaveKey('externalAccountBinding');
});

it('Account::create() sends configured EAB credentials even when the directory does not require them', function () {
    $sent = [];
    $api  = metaApi(['externalAccountRequired' => false], $sent, new \CoyoteCert\Provider\SslCom('kid', 'c2VjcmV0'));

    $api->account()->create();

    expect($sent[0])->toHaveKey('externalAccountBinding');
});

it('Account::create() requires EAB when the directory says so, whatever the provider class claims', function () {
    $sent = [];
    $api  = metaApi(['externalAccountRequired' => true], $sent);

    expect(fn() => $api->account()->create())->toThrow(AcmeException::class, 'requires EAB credentials');
});

it('Order::new() retries without replaces when the certificate belongs to another account', function () {
    $sent = [];
    $api  = replacesRetryApi(403, 'urn:ietf:params:acme:error:unauthorized', $sent);

    expect($api->order()->new(makeAccountData(), ['example.com'], '', 'aki.serial')->status)->toBe('pending');
    expect($sent[1])->not->toHaveKey('replaces');
});

it('Account::create() accepts 200 for a stored key that is already registered (RFC 8555 §7.3.1)', function () {
    $api = makeEndpointApi(closureMock(
        getHandler: fn($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn($url) => new Response(['location' => 'https://acme.example/account/9'], $url, 200, accountBody()),
    ), withKeyStorage());

    expect($api->account()->create()->url)->toBe('https://acme.example/account/9');
});
