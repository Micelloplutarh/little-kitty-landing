<?php
declare(strict_types=1);

namespace YourShield;

final class HmacSigner
{
    public function buildHeaders(
        string $method,
        string $path,
        string $body,
        string $siteKey,
        string $secret,
        string $apiVer
    ): array {
        $timestamp = (string) time();
        $nonce = Utils::randomToken(20);
        $bodyHash = hash('sha256', $body);

        $canonical = implode("\n", [
            strtoupper($method),
            $path,
            $timestamp,
            $nonce,
            $bodyHash,
            $siteKey,
            $apiVer,
        ]);

        $signature = hash_hmac('sha256', $canonical, $secret);

        return [
            'X-YS-SiteKey: ' . $siteKey,
            'X-YS-Timestamp: ' . $timestamp,
            'X-YS-Nonce: ' . $nonce,
            'X-YS-Body-Sha256: ' . $bodyHash,
            'X-YS-Signature: ' . $signature,
            'X-YS-Api-Version: ' . $apiVer,
        ];
    }
}
