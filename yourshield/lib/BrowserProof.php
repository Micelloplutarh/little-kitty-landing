<?php
declare(strict_types=1);

namespace YourShield;

final class BrowserProof
{
    public static function read(RuntimeConfig $config, CacheBackend $cache): ?string
    {
        if (($config->getArray('browser_proof')['enabled'] ?? true) !== true) {
            return null;
        }
        $cookie = (string) ($_COOKIE[self::cookieName($config)] ?? '');
        if (preg_match('/\A[a-f0-9]{64}\z/', $cookie) !== 1) {
            return null;
        }
        $proof = $cache->get('ys:browser_proof:v1:' . $cookie);
        return is_string($proof) && preg_match('/\A[a-f0-9]{64}\z/', $proof) === 1 ? $proof : null;
    }

    public static function store(RuntimeConfig $config, CacheBackend $cache, array $server, array $response): void
    {
        if (($config->getArray('browser_proof')['enabled'] ?? true) !== true) {
            return;
        }
        $proof = $response['browser_proof'] ?? null;
        $ttl = min(600, max(0, (int) ($response['proof_ttl'] ?? 0)));
        if (!is_string($proof) || preg_match('/\A[a-f0-9]{64}\z/', $proof) !== 1 || $ttl === 0) {
            return;
        }
        $cookie = bin2hex(random_bytes(32));
        $cache->set('ys:browser_proof:v1:' . $cookie, $proof, $ttl);
        setcookie(self::cookieName($config), $cookie, [
            'expires' => time() + $ttl,
            'path' => '/',
            'secure' => Utils::requestScheme($server, $config->getArray('trusted_proxy')) === 'https',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    private static function cookieName(RuntimeConfig $config): string
    {
        return 'ys_browser_v1_' . substr(hash('sha256', $config->cacheNamespace()), 0, 12);
    }
}
