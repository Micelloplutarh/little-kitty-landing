<?php
declare(strict_types=1);

namespace YourShield;

final class BrowserEscape
{
    public const CHECKED_COOKIE = 'tds_be_checked';
    public const SKIP_COOKIE = 'tds_be_skip';
    public const MARKER = '__tds_be';

    /** Remove only the UX marker; preserve every other raw query segment. */
    public static function stripMarker(string $target): array
    {
        $queryAt = strpos($target, '?');
        if ($queryAt === false) {
            return ['target' => $target, 'skip' => false];
        }
        $segments = [];
        $skip = false;
        $removed = false;
        foreach (explode('&', substr($target, $queryAt + 1)) as $segment) {
            if ($segment === self::MARKER . '=continue') {
                $removed = true;
                $skip = true;
            } else {
                $segments[] = $segment;
            }
        }
        return [
            'target' => $removed
                ? substr($target, 0, $queryAt) . ($segments !== [] ? '?' . implode('&', $segments) : '')
                : $target,
            'skip' => $skip,
        ];
    }

    public static function page(array $response, array $server): ?array
    {
        $page = $response['browser_escape'] ?? null;
        foreach (['rid', 'csrf', 'browser_proof', 'proof_ttl', 'continuation', 'ttl_allow_cache', 'allow_ttl'] as $field) {
            if (array_key_exists($field, $response) || (is_array($page) && array_key_exists($field, $page))) {
                return null;
            }
        }
        if (!Utils::isDocumentNavigation($server)
            || ($response['decision'] ?? null) !== 'challenge'
            || ($response['challenge_type'] ?? null) !== 'browser_escape'
            || !is_array($page)
            || ($page['version'] ?? null) !== 1
            || !in_array($page['phase'] ?? null, ['probe', 'escape'], true)
            || !in_array($page['platform'] ?? null, ['ios', 'android'], true)
            || !array_key_exists('app', $page)
            || (($page['phase'] === 'probe' && $page['app'] !== null)
                || ($page['phase'] === 'escape' && !in_array($page['app'], ['instagram', 'facebook', 'tiktok', 'vk', 'x', 'telegram'], true)))
            || !is_string($page['html'] ?? null)
            || trim($page['html']) === ''
            || strlen($page['html']) > 65536
        ) {
            return null;
        }
        return $page;
    }

    public static function restoreRequestMarker(string $order): void
    {
        unset($_REQUEST[self::MARKER]);
        foreach (str_split(strtoupper($order)) as $source) {
            $values = match ($source) {
                'G' => $_GET,
                'P' => $_POST,
                'C' => $_COOKIE,
                default => [],
            };
            if (array_key_exists(self::MARKER, $values)) {
                $current = $_REQUEST[self::MARKER] ?? null;
                $incoming = $values[self::MARKER];
                $_REQUEST[self::MARKER] = is_array($current) && is_array($incoming)
                    ? array_replace_recursive($current, $incoming)
                    : $incoming;
            }
        }
    }

    public static function setCookie(string $name, array $server, array $trustedProxyCfg): void
    {
        setcookie($name, '1', [
            'expires' => time() + 1800,
            'path' => '/',
            'secure' => Utils::requestScheme($server, $trustedProxyCfg) === 'https',
            'httponly' => false,
            'samesite' => 'Lax',
        ]);
    }
}
