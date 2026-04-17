<?php

use CoyoteCert\Api;
use CoyoteCert\DTO\AccountData;
use CoyoteCert\DTO\DomainValidationData;
use CoyoteCert\DTO\OrderData;
use CoyoteCert\Enums\AuthorizationChallengeEnum;
use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\AcmeException;
use CoyoteCert\Exceptions\OrderNotFoundException;
use CoyoteCert\Exceptions\RateLimitException;
use CoyoteCert\Http\Response;
use CoyoteCert\Interfaces\HttpClientInterface;
use CoyoteCert\Provider\CustomProvider;
use CoyoteCert\Storage\InMemoryStorage;

// ── Mock helpers ──────────────────────────────────────────────────────────────

function endpointMock(
    array|string $getBody = [],
    int $getCode = 200,
    array|string $postBody = [],
    int $postCode = 200,
    array $headHeaders = ['replay-nonce' => 'nonce123'],
): HttpClientInterface {
    return new class($getCode, $getBody, $postCode, $postBody, $headHeaders) implements HttpClientInterface {
        public function __construct(
            private int $getCode, private array|string $getBody,
            private int $postCode, private array|string $postBody,
            private array $headHeaders,
        ) {}
        public function head(string $url): Response { return new Response($this->headHeaders, $url, 200, ''); }
        public function get(string $url, array $headers = [], array $arguments = [], int $maxRedirects = 0): Response {
            return new Response([], $url, $this->getCode, $this->getBody);
        }
        public function post(string $url, array $payload = [], array $headers = [], int $maxRedirects = 0): Response {
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

function makeEndpointApi(HttpClientInterface $httpClient, ?InMemoryStorage $storage = null): Api
{
    return new Api(
        provider:   new CustomProvider(directoryUrl: 'https://acme.example/directory'),
        storage:    $storage ?? new InMemoryStorage(),
        httpClient: $httpClient,
    );
}

// ── Directory ─────────────────────────────────────────────────────────────────

it('Directory::all() throws on a 503 response', function () {
    $api = makeEndpointApi(endpointMock(getBody: ['detail' => 'Service Unavailable'], getCode: 503));

    expect(fn () => $api->directory()->all())
        ->toThrow(AcmeException::class, 'Cannot get directory');
});

it('Directory::getOrder() replaces new-order with order and appends a trailing slash', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()));

    expect($api->directory()->getOrder())->toBe('https://acme.example/order/');
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

    expect(fn () => $api->account()->get())
        ->toThrow(AcmeException::class, 'Local account keys not found');
});

it('Account::create() throws via throwError on a non-201 response', function () {
    $storage = new InMemoryStorage(); // empty — generateNewKeys() will populate it

    // GET returns the directory body; POST returns a 500 error
    $api = makeEndpointApi(
        endpointMock(
            getBody:  directoryBody(),
            getCode:  200,
            postBody: ['detail' => 'Internal Server Error'],
            postCode: 500,
        ),
        $storage,
    );

    expect(fn () => $api->account()->create('test@example.com'))
        ->toThrow(AcmeException::class);
});

// ── RenewalInfo ───────────────────────────────────────────────────────────────

it('RenewalInfo::get() returns null when renewalInfo is absent from the directory', function () {
    $storage = new InMemoryStorage();
    $storage->saveAccountKey(rsaKeyPem(), KeyType::RSA_2048);

    $api = makeEndpointApi(endpointMock(getBody: directoryBody(withRenewalInfo: false)), $storage);

    // certPem / issuerPem are irrelevant — the null path is hit before certId() runs
    expect($api->renewalInfo()->get('cert', 'issuer'))->toBeNull();
});

// ── Order ─────────────────────────────────────────────────────────────────────

it('Order::finalize() returns false when the order is not ready (status=pending)', function () {
    $storage = new InMemoryStorage();
    $storage->saveAccountKey(rsaKeyPem(), KeyType::RSA_2048);

    // No HTTP calls are made; the isReady() guard short-circuits before any I/O.
    $api = makeEndpointApi(endpointMock(), $storage);

    $orderData = new OrderData(
        id:                   '1',
        url:                  'https://acme.example/order/1',
        status:               'pending',
        expires:              '2099-01-01T00:00:00Z',
        identifiers:          [],
        domainValidationUrls: [],
        finalizeUrl:          'https://acme.example/finalize/1',
        accountUrl:           'https://acme.example/account/1',
        certificateUrl:       null,
        finalized:            false,
    );

    expect($api->order()->finalize($orderData, 'fake-csr'))->toBeFalse();
});

// ── Additional helpers ────────────────────────────────────────────────────────

/**
 * InMemoryStorage pre-seeded with an RSA-2048 account key.
 * Required by any test that calls createKeyId() (needs getPrivateKey()).
 */
function withKeyStorage(): InMemoryStorage
{
    $storage = new InMemoryStorage();
    $storage->saveAccountKey(rsaKeyPem(), KeyType::RSA_2048);
    return $storage;
}

/**
 * A flexible mock whose GET and POST behaviour is driven by closures,
 * allowing URL-based dispatch without a complex hand-rolled stub.
 */
function closureMock(
    ?callable $getHandler  = null,
    ?callable $postHandler = null,
    array     $headHeaders = ['replay-nonce' => 'nonce123'],
): HttpClientInterface {
    $getH  = $getHandler  ?? static fn ($url) => new Response([], $url, 200, []);
    $postH = $postHandler ?? static fn ($url) => new Response([], $url, 200, []);

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
        id:        '1',
        url:       'https://acme.example/account/1',
        key:       [],
        status:    'valid',
        agreement: '',
        createdAt: null,
    );
}

/** Pending OrderData. */
function pendingOrderData(): OrderData
{
    return new OrderData(
        id:                   '1',
        url:                  'https://acme.example/order/1',
        status:               'pending',
        expires:              '2099-01-01T00:00:00Z',
        identifiers:          [],
        domainValidationUrls: [],
        finalizeUrl:          'https://acme.example/finalize/1',
        accountUrl:           'https://acme.example/account/1',
        certificateUrl:       null,
        finalized:            false,
    );
}

/** Ready OrderData (status=ready, required for finalize). */
function readyOrderData(): OrderData
{
    return new OrderData(
        id:                   '1',
        url:                  'https://acme.example/order/1',
        status:               'ready',
        expires:              '2099-01-01T00:00:00Z',
        identifiers:          [],
        domainValidationUrls: [],
        finalizeUrl:          'https://acme.example/finalize/1',
        accountUrl:           'https://acme.example/account/1',
        certificateUrl:       null,
        finalized:            false,
    );
}

/** OrderData with specific authorisation URLs (for allChallengesPassed tests). */
function orderDataWithAuthzUrls(array $urls): OrderData
{
    return new OrderData(
        id:                   '1',
        url:                  'https://acme.example/order/1',
        status:               'pending',
        expires:              '2099-01-01T00:00:00Z',
        identifiers:          [],
        domainValidationUrls: $urls,
        finalizeUrl:          'https://acme.example/finalize/1',
        accountUrl:           'https://acme.example/account/1',
        certificateUrl:       null,
        finalized:            false,
    );
}

/**
 * Generates a self-signed leaf + issuer certificate pair.
 * Returns [$leafPem, $issuerPem].
 * serial: 1 on the leaf ensures an even-length hex serial for certId().
 */
function makeTestCerts(): array
{
    $issuerKey  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $issuerCsr  = openssl_csr_new(['commonName' => 'Test Issuer CA'], $issuerKey);
    $issuerCert = openssl_csr_sign($issuerCsr, null, $issuerKey, 3650, serial: 1);
    openssl_x509_export($issuerCert, $issuerPem);

    $leafKey  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $leafCsr  = openssl_csr_new(['commonName' => 'leaf.example.com'], $leafKey);
    $leafCert = openssl_csr_sign($leafCsr, $issuerCert, $issuerKey, 365, serial: 1);
    openssl_x509_export($leafCert, $leafPem);

    return [$leafPem, $issuerPem];
}

// ── Account ───────────────────────────────────────────────────────────────────

it('Account::get() succeeds when storage has a key and server returns 200', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn ($url) => new Response(
            ['location' => 'https://acme.example/account/1'],
            $url, 200,
            accountBody()
        ),
    );

    $account = makeEndpointApi($mock, $storage)->account()->get();

    expect($account->url)->toBe('https://acme.example/account/1');
    expect($account->status)->toBe('valid');
});

it('Account::get() throws via throwError when server returns non-200', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn ($url) => new Response([], $url, 403, ['detail' => 'Forbidden']),
    );

    expect(fn () => makeEndpointApi($mock, $storage)->account()->get())
        ->toThrow(AcmeException::class, 'Forbidden');
});

it('Account::create() throws when EAB is required but provider returns null credentials', function () {
    // ZeroSSL with no credentials: isEabRequired()=true, getEabCredentials()=null
    $api = new Api(
        provider:   new \CoyoteCert\Provider\ZeroSSL(),
        storage:    new InMemoryStorage(),
        httpClient: endpointMock(getBody: directoryBody()),
    );

    expect(fn () => $api->account()->create('test@example.com'))
        ->toThrow(AcmeException::class, 'requires EAB credentials');
});

it('Account::create() succeeds with valid EAB credentials', function () {
    $api = new Api(
        provider: new CustomProvider(
            directoryUrl: 'https://acme.example/directory',
            eabKid:       'kid1',
            eabHmac:      'c2VjcmV0', // base64url('secret')
        ),
        storage:    new InMemoryStorage(),
        httpClient: closureMock(
            getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
            postHandler: fn ($url) => new Response(
                ['location' => 'https://acme.example/account/1'],
                $url, 201,
                accountBody()
            ),
        ),
    );

    $account = $api->account()->create('test@example.com');
    expect($account->url)->toBe('https://acme.example/account/1');
});

it('Account::create() succeeds without EAB when server returns 201 with location header', function () {
    // Non-EAB provider (Pebble) — covers the non-EAB create() success path
    $api = new Api(
        provider:   new \CoyoteCert\Provider\Pebble(),
        storage:    new InMemoryStorage(),
        httpClient: closureMock(
            getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
            postHandler: fn ($url) => new Response(
                ['location' => 'https://acme.example/account/1'],
                $url, 201,
                accountBody()
            ),
        ),
    );

    $account = $api->account()->create('test@example.com');
    expect($account->url)->toBe('https://acme.example/account/1');
});

// ── Order ─────────────────────────────────────────────────────────────────────

it('Order::new() throws for domains with multiple wildcards', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), new InMemoryStorage());

    expect(fn () => $api->order()->new(makeAccountData(), ['*.*.example.com']))
        ->toThrow(AcmeException::class, 'multiple wildcards');
});

it('Order::new() throws when response is not 201', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: ['detail' => 'Bad Request'],
        postCode: 400,
    ), withKeyStorage());

    expect(fn () => $api->order()->new(makeAccountData(), ['example.com']))
        ->toThrow(AcmeException::class, 'Creating new order failed');
});

it('Order::new() returns OrderData on 201 response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
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
            directoryUrl:      'https://acme.example/directory',
            profilesSupported: true,
        ),
        storage:    withKeyStorage(),
        httpClient: endpointMock(
            getBody:  directoryBody(),
            postBody: orderBody('pending'),
            postCode: 201,
        ),
    );

    $order = $api->order()->new(makeAccountData(), ['example.com'], 'shortlived');
    expect($order)->toBeInstanceOf(OrderData::class);
});

it('Order::refresh() returns updated OrderData', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: orderBody('ready'),
        postCode: 200,
    ), withKeyStorage());

    $refreshed = $api->order()->refresh(pendingOrderData());
    expect($refreshed->status)->toBe('ready');
});

it('Order::waitUntilValid() returns OrderData when status becomes valid', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: orderBody('valid'),
        postCode: 200,
    ), withKeyStorage());

    $valid = $api->order()->waitUntilValid(pendingOrderData(), 1, 0);
    expect($valid->status)->toBe('valid');
});

it('Order::waitUntilValid() throws when order becomes invalid', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: orderBody('invalid'),
        postCode: 200,
    ), withKeyStorage());

    expect(fn () => $api->order()->waitUntilValid(pendingOrderData(), 1, 0))
        ->toThrow(AcmeException::class, 'invalid');
});

it('Order::waitUntilValid() throws after exhausting max attempts', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: orderBody('processing'),
        postCode: 200,
    ), withKeyStorage());

    expect(fn () => $api->order()->waitUntilValid(pendingOrderData(), 1, 0))
        ->toThrow(AcmeException::class, 'did not become valid');
});

it('Order::finalize() returns true on 200 response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: orderBody('valid', 'https://acme.example/cert/1'),
        postCode: 200,
    ), withKeyStorage());

    expect($api->order()->finalize(readyOrderData(), base64_encode('fake-csr')))->toBeTrue();
});

it('Order::finalize() returns false on non-200 response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: ['detail' => 'Forbidden'],
        postCode: 403,
    ), withKeyStorage());

    expect($api->order()->finalize(readyOrderData(), base64_encode('fake-csr')))->toBeFalse();
});

it('Order::finalize() extracts base64 from a PEM-formatted CSR', function () {
    // Generate a real PEM CSR so the regex extraction path (lines 130–132) is covered
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $csr = openssl_csr_new(['commonName' => 'example.com'], $key);
    openssl_csr_export($csr, $csrPem);

    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: orderBody('valid', 'https://acme.example/cert/1'),
        postCode: 200,
    ), withKeyStorage());

    expect($api->order()->finalize(readyOrderData(), $csrPem))->toBeTrue();
});

it('Order::get() throws OrderNotFoundException on 404', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn ($url) => str_contains($url, 'directory')
            ? new Response([], $url, 200, directoryBody())
            : new Response([], $url, 404, ['detail' => 'Order not found']),
        postHandler: fn ($url) => new Response(
            ['location' => 'https://acme.example/account/1'],
            $url, 200,
            accountBody()
        ),
    );

    expect(fn () => makeEndpointApi($mock, $storage)->order()->get('missing'))
        ->toThrow(OrderNotFoundException::class, 'Order not found');
});

it('Order::get() throws RateLimitException on 429', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn ($url) => str_contains($url, 'directory')
            ? new Response([], $url, 200, directoryBody())
            : new Response([], $url, 429, ['detail' => 'Too many requests']),
        postHandler: fn ($url) => new Response(
            ['location' => 'https://acme.example/account/1'],
            $url, 200,
            accountBody()
        ),
    );

    expect(fn () => makeEndpointApi($mock, $storage)->order()->get('spam'))
        ->toThrow(RateLimitException::class, 'Too many requests');
});

it('Order::get() throws AcmeException on 500', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn ($url) => str_contains($url, 'directory')
            ? new Response([], $url, 200, directoryBody())
            : new Response([], $url, 500, ['detail' => 'Internal error']),
        postHandler: fn ($url) => new Response(
            ['location' => 'https://acme.example/account/1'],
            $url, 200,
            accountBody()
        ),
    );

    expect(fn () => makeEndpointApi($mock, $storage)->order()->get('fail'))
        ->toThrow(AcmeException::class, 'Internal error');
});

it('Order::get() returns OrderData on success', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler: fn ($url) => str_contains($url, 'directory')
            ? new Response([], $url, 200, directoryBody())
            : new Response([], $url, 200, orderBody('valid')),
        postHandler: fn ($url) => new Response(
            ['location' => 'https://acme.example/account/1'],
            $url, 200,
            accountBody()
        ),
    );

    $order = makeEndpointApi($mock, $storage)->order()->get('1');
    expect($order->status)->toBe('valid');
});

// ── DomainValidation ──────────────────────────────────────────────────────────

it('DomainValidation::status() silently skips non-200 responses', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: ['detail' => 'Forbidden'],
        postCode: 403,
    ), withKeyStorage());

    $order = orderDataWithAuthzUrls(['https://acme.example/authz/1']);

    // Non-200 response is logged and skipped — no exception, empty result.
    expect($api->domainValidation()->status($order))->toBeEmpty();
});

it('DomainValidation::getValidationData() builds HTTP validation item', function () {
    $storage = withKeyStorage();
    $api     = makeEndpointApi(endpointMock(), $storage);

    $challenge = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             ['type' => 'http-01', 'token' => 'abc123', 'url' => 'https://acme.example/ch/1'],
        dns:              [],
        dnsPersist:       [],
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
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             [],
        dns:              ['type' => 'dns-01', 'token' => 'dns-tok', 'url' => 'https://acme.example/ch/2'],
        dnsPersist:       [],
        validationRecord: [],
    );

    $data = $api->domainValidation()->getValidationData([$challenge], AuthorizationChallengeEnum::DNS);

    expect($data)->toHaveCount(1);
    expect($data[0])->toBeInstanceOf(\CoyoteCert\DTO\Dns01ValidationData::class);
    expect($data[0]->name)->toBe('_acme-challenge');
    expect($data[0]->identifier)->toBe('example.com');
});

it('DomainValidation::getValidationData() builds DNS_PERSIST validation item', function () {
    $storage = withKeyStorage();
    $api     = makeEndpointApi(endpointMock(), $storage);

    $challenge = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             [],
        dns:              [],
        dnsPersist:       ['type' => 'dns-persist-01', 'token' => 'persist-tok', 'url' => 'https://acme.example/ch/3'],
        validationRecord: [],
    );

    $data = $api->domainValidation()->getValidationData([$challenge], AuthorizationChallengeEnum::DNS_PERSIST);

    expect($data)->toHaveCount(1);
    expect($data[0])->toBeInstanceOf(\CoyoteCert\DTO\Dns01ValidationData::class);
    expect($data[0]->identifier)->toBe('example.com');
});

it('DomainValidation::getValidationData() with null challenge type returns matching types', function () {
    $storage = withKeyStorage();
    $api     = makeEndpointApi(endpointMock(), $storage);

    $challenge = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             ['type' => 'http-01', 'token' => 'http-tok', 'url' => 'https://acme.example/ch/1'],
        dns:              ['type' => 'dns-01',  'token' => 'dns-tok',  'url' => 'https://acme.example/ch/2'],
        dnsPersist:       [],
        validationRecord: [],
    );

    // null = all types; should return both HTTP and DNS items
    $data = $api->domainValidation()->getValidationData([$challenge], null);
    expect($data)->toHaveCount(2);
});

it('DomainValidation::start() sends HTTP challenge with localTest=false', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: [],
        postCode: 200,
    ), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             ['type' => 'http-01', 'token' => 'tok', 'url' => 'https://acme.example/ch/1'],
        dns:              [],
        dnsPersist:       [],
        validationRecord: [],
    );

    $response = $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::HTTP, false);
    expect($response->getHttpResponseCode())->toBe(200);
});

it('DomainValidation::start() sends DNS challenge with localTest=false', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: [],
        postCode: 200,
    ), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             [],
        dns:              ['type' => 'dns-01', 'token' => 'tok', 'url' => 'https://acme.example/ch/2'],
        dnsPersist:       [],
        validationRecord: [],
    );

    $response = $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::DNS, false);
    expect($response->getHttpResponseCode())->toBe(200);
});

it('DomainValidation::start() sends DNS_PERSIST challenge with localTest=false', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: [],
        postCode: 200,
    ), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             [],
        dns:              [],
        dnsPersist:       ['type' => 'dns-persist-01', 'token' => 'tok', 'url' => 'https://acme.example/ch/3'],
        validationRecord: [],
    );

    $response = $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::DNS_PERSIST, false);
    expect($response->getHttpResponseCode())->toBe(200);
});

it('DomainValidation::start() with localTest=true passes HTTP local check when body matches', function () {
    $storage    = withKeyStorage();
    $thumbprint = \CoyoteCert\Support\Thumbprint::make($storage->getAccountKey());
    $token      = 'local-test-token';
    $keyAuth    = $token . '.' . $thumbprint;

    $mock = closureMock(
        getHandler:  fn ($url) => str_contains($url, 'directory')
            ? new Response([], $url, 200, directoryBody())
            : new Response([], $url, 200, $keyAuth),
        postHandler: fn ($url) => new Response([], $url, 200, []),
    );

    $dvd = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             ['type' => 'http-01', 'token' => $token, 'url' => 'https://acme.example/ch/1'],
        dns:              [],
        dnsPersist:       [],
        validationRecord: [],
    );

    $response = makeEndpointApi($mock, $storage)->domainValidation()
        ->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::HTTP, true);

    expect($response->getHttpResponseCode())->toBe(200);
});

it('DomainValidation::start() with localTest=true fails DNS check (covers DNS local-test path)', function () {
    // DNS local-test always fails in unit tests (no real DNS TXT record deployed).
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             [],
        dns:              ['type' => 'dns-01', 'token' => 'unit-test-token', 'url' => 'https://acme.example/ch/2'],
        dnsPersist:       [],
        validationRecord: [],
    );

    expect(fn () => $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::DNS, true))
        ->toThrow(\CoyoteCert\Exceptions\DomainValidationException::class);
});

it('DomainValidation::start() with localTest=true fails DNS_PERSIST check (covers DNS_PERSIST local-test path)', function () {
    // DNS_PERSIST local-test follows the same DNS path — always fails without a real record.
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             [],
        dns:              [],
        dnsPersist:       ['type' => 'dns-persist-01', 'token' => 'unit-test-token', 'url' => 'https://acme.example/ch/3'],
        validationRecord: [],
    );

    expect(fn () => $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::DNS_PERSIST, true))
        ->toThrow(\CoyoteCert\Exceptions\DomainValidationException::class);
});

it('DomainValidation::start() throws DomainValidationException when challenge data is empty', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             [],
        dns:              [],  // empty — no DNS challenge available
        dnsPersist:       [],
        validationRecord: [],
    );

    expect(fn () => $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::DNS, false))
        ->toThrow(\CoyoteCert\Exceptions\DomainValidationException::class, 'No dns-01 challenge found');
});

it('DomainValidation::start() logs error when challenge POST returns >= 400', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: ['detail' => 'Bad challenge'],
        postCode: 400,
    ), withKeyStorage());

    $dvd = new DomainValidationData(
        identifier:       ['type' => 'dns', 'value' => 'example.com'],
        status:           'pending',
        expires:          '2099-01-01T00:00:00Z',
        file:             ['type' => 'http-01', 'token' => 'tok', 'url' => 'https://acme.example/ch/1'],
        dns:              [],
        dnsPersist:       [],
        validationRecord: [],
    );

    // start() logs the error but still returns the response without throwing.
    $response = $api->domainValidation()->start(makeAccountData(), $dvd, AuthorizationChallengeEnum::HTTP, false);
    expect($response->getHttpResponseCode())->toBe(400);
});

it('DomainValidation::allChallengesPassed() returns true immediately when no authz URLs', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    // Empty domainValidationUrls → status() returns [] (falsy) → loop never executes
    expect($api->domainValidation()->allChallengesPassed(orderDataWithAuthzUrls([])))->toBeTrue();
});

it('DomainValidation::allChallengesPassed() returns true when all challenges are valid on first try', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
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
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
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
        orderDataWithAuthzUrls(['https://acme.example/authz/1'])
    ))->toBeTrue();
});

it('DomainValidation::allChallengesPassed() returns false after 4 consecutive failures', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
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
        orderDataWithAuthzUrls(['https://acme.example/authz/1'])
    ))->toBeFalse();
});

// ── Certificate ───────────────────────────────────────────────────────────────

it('Certificate::getBundle() returns CertificateBundleData on 200', function () {
    $certPem = "-----BEGIN CERTIFICATE-----\nMIIBtest==\n-----END CERTIFICATE-----\n";

    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: $certPem,
        postCode: 200,
    ), withKeyStorage());

    $order = new OrderData(
        id:                   '1',
        url:                  'https://acme.example/order/1',
        status:               'valid',
        expires:              '2099-01-01T00:00:00Z',
        identifiers:          [],
        domainValidationUrls: [],
        finalizeUrl:          'https://acme.example/finalize/1',
        accountUrl:           'https://acme.example/account/1',
        certificateUrl:       'https://acme.example/cert/1',
        finalized:            true,
    );

    $bundle = $api->certificate()->getBundle($order);
    expect($bundle->certificate)->toContain('-----BEGIN CERTIFICATE-----');
});

it('Certificate::getBundle() throws on non-200 response', function () {
    $api = makeEndpointApi(endpointMock(
        getBody:  directoryBody(),
        postBody: ['detail' => 'Not Found'],
        postCode: 404,
    ), withKeyStorage());

    $order = new OrderData(
        id: '1', url: 'https://acme.example/order/1', status: 'valid',
        expires: '2099-01-01T00:00:00Z', identifiers: [], domainValidationUrls: [],
        finalizeUrl: 'https://acme.example/finalize/1',
        accountUrl:  'https://acme.example/account/1',
        certificateUrl: 'https://acme.example/cert/1',
        finalized: true,
    );

    expect(fn () => $api->certificate()->getBundle($order))
        ->toThrow(AcmeException::class, 'Failed to fetch certificate');
});

it('Certificate::revoke() throws when PEM is invalid', function () {
    $api = makeEndpointApi(endpointMock(getBody: directoryBody()), withKeyStorage());

    expect(fn () => $api->certificate()->revoke('not-a-valid-cert'))
        ->toThrow(AcmeException::class, 'Could not parse the certificate');
});

it('Certificate::revoke() returns true on successful revocation', function () {
    $storage = withKeyStorage();
    $key     = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $csr     = openssl_csr_new(['commonName' => 'test.example.com'], $key);
    $cert    = openssl_csr_sign($csr, null, $key, 365);
    openssl_x509_export($cert, $certPem);

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn ($url) => str_contains($url, 'account')
            ? new Response(['location' => 'https://acme.example/account/1'], $url, 200, accountBody())
            : new Response([], $url, 200, []),
    );

    expect(makeEndpointApi($mock, $storage)->certificate()->revoke($certPem))->toBeTrue();
});

it('Certificate::revoke() returns false when server rejects revocation', function () {
    $storage = withKeyStorage();
    $key     = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $csr     = openssl_csr_new(['commonName' => 'test.example.com'], $key);
    $cert    = openssl_csr_sign($csr, null, $key, 365);
    openssl_x509_export($cert, $certPem);

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn ($url) => str_contains($url, 'account')
            ? new Response(['location' => 'https://acme.example/account/1'], $url, 200, accountBody())
            : new Response([], $url, 403, ['detail' => 'Forbidden']),
    );

    expect(makeEndpointApi($mock, $storage)->certificate()->revoke($certPem))->toBeFalse();
});

// ── RenewalInfo ───────────────────────────────────────────────────────────────

it('RenewalInfo::get() returns a RenewalWindow when server responds 200', function () {
    $storage = withKeyStorage();
    [$leafPem, $issuerPem] = makeTestCerts();

    $renewalBody = [
        'suggestedWindow' => [
            'start' => '2026-04-01T00:00:00Z',
            'end'   => '2026-04-15T00:00:00Z',
        ],
        'explanationURL' => 'https://acme.example/why',
    ];

    $mock = closureMock(
        getHandler: fn ($url) => str_contains($url, 'ari/')
            ? new Response([], $url, 200, $renewalBody)
            : new Response([], $url, 200, directoryBody(withRenewalInfo: true)),
    );

    $window = makeEndpointApi($mock, $storage)->renewalInfo()->get($leafPem, $issuerPem);

    expect($window)->not->toBeNull();
    expect($window->explanationUrl)->toBe('https://acme.example/why');
});

it('RenewalInfo::get() returns null when ARI endpoint returns non-200', function () {
    $storage = withKeyStorage();
    [$leafPem, $issuerPem] = makeTestCerts();

    $mock = closureMock(
        getHandler: fn ($url) => str_contains($url, 'ari/')
            ? new Response([], $url, 404, [])
            : new Response([], $url, 200, directoryBody(withRenewalInfo: true)),
    );

    expect(makeEndpointApi($mock, $storage)->renewalInfo()->get($leafPem, $issuerPem))->toBeNull();
});

// ── badNonce retry ────────────────────────────────────────────────────────────

it('postSigned() retries once on badNonce and succeeds (KID path)', function () {
    $storage = withKeyStorage();
    $calls   = 0;

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
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
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
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
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn ($url) => new Response([], $url, 200, array_merge(accountBody(), ['contact' => $contact])),
    );

    $updated = makeEndpointApi($mock, $storage)->account()->update(makeAccountData(), $contact);

    expect($updated->contact)->toBe($contact);
    expect($updated->status)->toBe('valid');
});

it('Account::update() throws on non-200 response', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn ($url) => new Response([], $url, 403, ['detail' => 'Unauthorized']),
    );

    expect(fn () => makeEndpointApi($mock, $storage)->account()->update(makeAccountData(), []))
        ->toThrow(AcmeException::class, 'Unauthorized');
});

// ── Account::deactivate() ─────────────────────────────────────────────────────

it('Account::deactivate() returns account with status=deactivated on success', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn ($url) => new Response([], $url, 200, array_merge(accountBody(), ['status' => 'deactivated'])),
    );

    $updated = makeEndpointApi($mock, $storage)->account()->deactivate(makeAccountData());
    expect($updated->status)->toBe('deactivated');
});

it('Account::deactivate() throws on non-200 response', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: fn ($url) => new Response([], $url, 400, ['detail' => 'Bad Request']),
    );

    expect(fn () => makeEndpointApi($mock, $storage)->account()->deactivate(makeAccountData()))
        ->toThrow(AcmeException::class);
});

// ── Account::keyRollover() ────────────────────────────────────────────────────

function directoryBodyWithKeyChange(bool $withRenewalInfo = false): array
{
    return array_merge(directoryBody($withRenewalInfo), ['keyChange' => 'https://acme.example/key-change']);
}

it('Account::keyRollover() saves a new RSA key and returns AccountData on success', function () {
    $storage = withKeyStorage();
    $oldKey  = $storage->getAccountKey();

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
        postHandler: fn ($url) => new Response([], $url, 200, accountBody()),
    );

    $result = makeEndpointApi($mock, $storage)->account()->keyRollover(makeAccountData());

    expect($result->status)->toBe('valid');
    expect($storage->getAccountKey())->not->toBe($oldKey);
});

it('Account::keyRollover() saves a new EC key when the account key is EC', function () {
    $storage = new InMemoryStorage();
    $storage->saveAccountKey(ecKeyPem(), KeyType::EC_P256);
    $oldKey = $storage->getAccountKey();

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
        postHandler: fn ($url) => new Response([], $url, 200, accountBody()),
    );

    $result = makeEndpointApi($mock, $storage)->account()->keyRollover(makeAccountData());

    expect($result->status)->toBe('valid');
    expect($storage->getAccountKey())->not->toBe($oldKey);
});

it('Account::keyRollover() retries once on badNonce', function () {
    $storage = withKeyStorage();
    $calls   = 0;

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
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

    $result = makeEndpointApi($mock, $storage)->account()->keyRollover(makeAccountData());
    expect($result->status)->toBe('valid');
    expect($calls)->toBe(2);
});

it('Account::keyRollover() throws on non-200 response', function () {
    $storage = withKeyStorage();

    $mock = closureMock(
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBodyWithKeyChange()),
        postHandler: fn ($url) => new Response([], $url, 400, ['detail' => 'Key rollover failed']),
    );

    expect(fn () => makeEndpointApi($mock, $storage)->account()->keyRollover(makeAccountData()))
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
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
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
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
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
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
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
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use (&$callCount) {
            $callCount++;
            // Two processing rounds then valid — no Retry-After header
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
        getHandler:  fn ($url) => new Response([], $url, 200, directoryBody()),
        postHandler: function ($url) use (&$callCount) {
            $callCount++;
            $status = $callCount === 1 ? 'pending' : 'valid';
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
        orderDataWithAuthzUrls(['https://acme.example/authz/1'])
    );

    expect($passed)->toBeTrue();
    expect($callCount)->toBe(2); // pending → valid after one retry
});

// ── RenewalInfo::certId() ─────────────────────────────────────────────────────

it('RenewalInfo::certId() returns a string in issuerHash.serial format', function () {
    $storage = withKeyStorage();
    [$leafPem, $issuerPem] = makeTestCerts();

    $mock   = closureMock(getHandler: fn ($url) => new Response([], $url, 200, directoryBody(withRenewalInfo: true)));
    $certId = makeEndpointApi($mock, $storage)->renewalInfo()->certId($leafPem, $issuerPem);

    expect($certId)->toBeString();
    $parts = explode('.', $certId);
    expect($parts)->toHaveCount(2);
    expect($parts[0])->not->toBeEmpty();
    expect($parts[1])->not->toBeEmpty();
});
