<?php
declare(strict_types=1);

namespace YourShield;

final class ApcuCache implements CacheBackend
{
    private string $prefix;
    private int $lockWaitMs;
    private int $lockTtlSec;

    public function __construct(string $prefix = 'ys:', int $lockWaitMs = 500, int $lockTtlSec = 5)
    {
        $this->prefix = $prefix;
        $this->lockWaitMs = max(1, $lockWaitMs);
        $this->lockTtlSec = max(1, $lockTtlSec);
    }

    public static function isAvailable(): bool
    {
        if (!function_exists('apcu_fetch') || !function_exists('apcu_store')) {
            return false;
        }

        if (!filter_var((string) ini_get('apc.enabled'), FILTER_VALIDATE_BOOLEAN)) {
            return false;
        }

        if (PHP_SAPI === 'cli' && !filter_var((string) ini_get('apc.enable_cli'), FILTER_VALIDATE_BOOLEAN)) {
            return false;
        }

        return true;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $success = false;
        $value = apcu_fetch($this->key($key), $success);
        return $success ? $value : $default;
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        apcu_store($this->key($key), $value, max(1, $ttlSeconds));
    }

    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        return apcu_add($this->key($key), $value, max(1, $ttlSeconds));
    }

    public function delete(string $key): void
    {
        apcu_delete($this->key($key));
    }

    public function mutate(string $key, int $ttlSeconds, callable $updater, mixed $default = null): mixed
    {
        $lockKey = $this->lockKey($key);
        $started = microtime(true);

        while (!apcu_add($lockKey, 1, $this->lockTtlSec)) {
            $elapsedMs = (int) round((microtime(true) - $started) * 1000);
            if ($elapsedMs >= $this->lockWaitMs) {
                throw new \RuntimeException('APCu mutate lock timeout for key: ' . $key);
            }
            usleep(10000);
        }

        try {
            $success = false;
            $current = apcu_fetch($this->key($key), $success);
            if (!$success) {
                $current = $default;
            }

            $next = $updater($current);
            apcu_store($this->key($key), $next, max(1, $ttlSeconds));
            return $next;
        } finally {
            apcu_delete($lockKey);
        }
    }

    private function key(string $key): string
    {
        return $this->prefix . $key;
    }

    private function lockKey(string $key): string
    {
        return $this->prefix . 'lock:' . $key;
    }
}
