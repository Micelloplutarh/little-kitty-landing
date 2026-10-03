<?php
declare(strict_types=1);

namespace YourShield;

final class RedisCache implements CacheBackend
{
    private \Redis $redis;
    private string $prefix;
    private int $lockWaitMs;
    private int $lockTtlSec;

    public function __construct(\Redis $redis, string $prefix = 'ys:', int $lockWaitMs = 500, int $lockTtlSec = 5)
    {
        $this->redis = $redis;
        $this->prefix = $prefix;
        $this->lockWaitMs = max(1, $lockWaitMs);
        $this->lockTtlSec = max(1, $lockTtlSec);
    }

    public static function extensionAvailable(): bool
    {
        return class_exists('Redis');
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $raw = $this->redis->get($this->key($key));
        if (!is_string($raw)) {
            return $default;
        }
        return $this->decode($raw, $default);
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->redis->setex($this->key($key), max(1, $ttlSeconds), $this->encode($value));
    }

    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        $redisKey = $this->key($key);
        $ttl = max(1, $ttlSeconds);
        $encoded = $this->encode($value);

        try {
            $result = $this->redis->set($redisKey, $encoded, ['nx', 'ex' => $ttl]);
            return $result === true || $result === 'OK';
        } catch (\Throwable) {
            $ok = (bool) $this->redis->setnx($redisKey, $encoded);
            if ($ok) {
                $this->redis->expire($redisKey, $ttl);
            }
            return $ok;
        }
    }

    public function delete(string $key): void
    {
        $this->redis->del($this->key($key));
    }

    public function mutate(string $key, int $ttlSeconds, callable $updater, mixed $default = null): mixed
    {
        $lockKey = $this->lockKey($key);
        $token = bin2hex(random_bytes(16));
        $started = microtime(true);

        while (!$this->acquireLock($lockKey, $token)) {
            $elapsedMs = (int) round((microtime(true) - $started) * 1000);
            if ($elapsedMs >= $this->lockWaitMs) {
                throw new \RuntimeException('Redis mutate lock timeout for key: ' . $key);
            }
            usleep(10000);
        }

        try {
            $raw = $this->redis->get($this->key($key));
            $current = is_string($raw) ? $this->decode($raw, $default) : $default;
            $next = $updater($current);
            $this->redis->setex($this->key($key), max(1, $ttlSeconds), $this->encode($next));
            return $next;
        } finally {
            $this->releaseLock($lockKey, $token);
        }
    }

    private function acquireLock(string $lockKey, string $token): bool
    {
        try {
            $result = $this->redis->set($lockKey, $token, ['nx', 'ex' => $this->lockTtlSec]);
            return $result === true || $result === 'OK';
        } catch (\Throwable) {
            $ok = (bool) $this->redis->setnx($lockKey, $token);
            if ($ok) {
                $this->redis->expire($lockKey, $this->lockTtlSec);
            }
            return $ok;
        }
    }

    private function releaseLock(string $lockKey, string $token): void
    {
        $script = <<<'LUA'
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
LUA;
        try {
            $this->redis->eval($script, [$lockKey, $token], 1);
        } catch (\Throwable) {
            $current = $this->redis->get($lockKey);
            if (is_string($current) && hash_equals($current, $token)) {
                $this->redis->del($lockKey);
            }
        }
    }

    private function encode(mixed $value): string
    {
        return base64_encode(serialize($value));
    }

    private function decode(string $raw, mixed $default = null): mixed
    {
        $decoded = base64_decode($raw, true);
        if (!is_string($decoded)) {
            return $default;
        }

        $value = @unserialize($decoded);
        if ($value === false && $decoded !== serialize(false)) {
            return $default;
        }
        return $value;
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
