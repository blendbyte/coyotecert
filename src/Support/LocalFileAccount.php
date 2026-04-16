<?php

namespace CoyoteCert\Support;

use CoyoteCert\Enums\KeyType;
use CoyoteCert\Exceptions\CryptoException;
use CoyoteCert\Exceptions\StorageException;
use CoyoteCert\Interfaces\AcmeAccountInterface;
use CoyoteCert\Support\OpenSsl;

class LocalFileAccount implements AcmeAccountInterface
{
    private string $accountName;

    public function __construct(private string $accountKeysPath)
    {
        // Make sure the path ends with a slash.
        $this->accountKeysPath = rtrim($this->accountKeysPath, '/').'/';
        $this->accountName = 'account_'.substr(hash('sha256', $this->accountKeysPath), 0, 16);
    }

    public function getPrivateKey(): string
    {
        return $this->getKey('private');
    }

    public function getPublicKey(): string
    {
        return $this->getKey('public');
    }

    public function exists(): bool
    {
        if (is_dir($this->accountKeysPath)) {
            return is_file($this->accountKeysPath.$this->getKeyName('private'))
                && is_file($this->accountKeysPath.$this->getKeyName('public'));
        }

        return false;
    }

    public function generateNewKeys(KeyType $keyType = KeyType::EC_P256): bool
    {
        $dir = rtrim($this->accountKeysPath, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;

        if (!is_dir($dir) && !mkdir($dir) && !is_dir($dir)) {
            throw new StorageException(sprintf('Directory "%s" was not created', $dir));
        }

        $key        = OpenSsl::generateKey($keyType);
        $privateKey = OpenSsl::openSslKeyToString($key);
        $keyDetails = openssl_pkey_get_details($key);

        if ($keyDetails === false) {
            throw new CryptoException('Failed to get key details.');
        }

        $publicKey = $keyDetails['key'];

        $privateKeyPath = $dir.$this->getKeyName('private');
        $publicKeyPath  = $dir.$this->getKeyName('public');

        if (file_put_contents($privateKeyPath, $privateKey) === false ||
            file_put_contents($publicKeyPath, $publicKey) === false) {
            throw new StorageException('Failed to write keys to files.');
        }

        return true;
    }

    public function savePrivateKey(string $pem, KeyType $keyType): void
    {
        $privateKeyPath = $this->accountKeysPath.$this->getKeyName('private');

        if (file_put_contents($privateKeyPath, $pem) === false) {
            throw new StorageException('Failed to write private key to file.');
        }

        // Derive and persist the new public key
        $privateKeyResource = openssl_pkey_get_private($pem);

        if ($privateKeyResource === false) {
            throw new CryptoException('Cannot load private key from PEM.');
        }

        $details = openssl_pkey_get_details($privateKeyResource);

        if ($details === false) {
            throw new CryptoException('Failed to get key details.');
        }

        $publicKeyPath = $this->accountKeysPath.$this->getKeyName('public');

        if (file_put_contents($publicKeyPath, $details['key']) === false) {
            throw new StorageException('Failed to write public key to file.');
        }
    }

    protected function getKey(string $type): string
    {
        $filePath = $this->accountKeysPath.$this->getKeyName($type);

        if (!file_exists($filePath)) {
            throw new StorageException(sprintf('[%s] File does not exist', $filePath));
        }

        $content = file_get_contents($filePath);

        if ($content === false) {
            throw new StorageException(sprintf('[%s] Failed to get contents of the file', $filePath));
        }

        return $content;
    }

    private function getKeyName(string $type): string
    {
        if (empty($this->accountName)) {
            throw new StorageException('Account name is not set.');
        }

        return sprintf('%s-%s.pem', $this->accountName, $type);
    }
}
