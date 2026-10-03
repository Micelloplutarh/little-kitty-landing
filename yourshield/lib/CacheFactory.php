<?php
declare(strict_types=1);

namespace YourShield;

final class CacheFactory
{
    public static function create(RuntimeConfig $config, ?callable $logger = null): CacheBackend
    {
        $cacheCfg = $config->getArray('cache');
        $namespace = $config->cacheNamespace();
        $prefix = (string) ($cacheCfg['prefix'] ?? 'ys:');
        $cacheCfg['apcu_prefix'] = (string) ($cacheCfg['apcu_prefix'] ?? $prefix) . $namespace;
        $redisCfg = is_array($cacheCfg['redis'] ?? null) ? $cacheCfg['redis'] : [];
        $redisCfg['prefix'] = (string) ($redisCfg['prefix'] ?? $prefix) . $namespace;
        $cacheCfg['redis'] = $redisCfg;
        $driver = strtolower(trim((string) ($cacheCfg['driver'] ?? 'auto')));
        if ($driver === '') {
            $driver = 'auto';
        }

        if ($driver === 'file') {
            return self::createFile($config);
        }
        if ($driver === 'apcu') {
            $apcu = self::createApcu($cacheCfg, $logger);
            if ($apcu !== null) {
                return $apcu;
            }
            self::log($logger, 'warning', 'APCu driver unavailable, falling back to file cache');
            return self::createFile($config);
        }
        if ($driver === 'redis') {
            $redis = self::createRedis($cacheCfg, $logger);
            if ($redis !== null) {
                return $redis;
            }
            self::log($logger, 'warning', 'Redis driver unavailable, falling back to file cache');
            return self::createFile($config);
        }

        // auto: APCu -> Redis -> File
        $apcu = self::createApcu($cacheCfg, $logger);
        if ($apcu !== null) {
            self::log($logger, 'info', 'Cache backend selected: APCu');
            return $apcu;
        }

        $redis = self::createRedis($cacheCfg, $logger);
        if ($redis !== null) {
            self::log($logger, 'info', 'Cache backend selected: Redis');
            return $redis;
        }

        self::log($logger, 'info', 'Cache backend selected: FileCache');
        return self::createFile($config);
    }

    private static function createFile(RuntimeConfig $config): CacheBackend
    {
        return new FileCache($config->getString('cache_dir'), $config->cacheNamespace());
    }

    private static function createApcu(array $cacheCfg, ?callable $logger = null): ?CacheBackend
    {
        if (!ApcuCache::isAvailable()) {
            return null;
        }

        $prefix = (string) ($cacheCfg['prefix'] ?? 'ys:');
        $apcuPrefix = (string) ($cacheCfg['apcu_prefix'] ?? $prefix);
        $lockWaitMs = is_numeric($cacheCfg['lock_wait_ms'] ?? null) ? (int) $cacheCfg['lock_wait_ms'] : 500;
        $lockTtlSec = is_numeric($cacheCfg['lock_ttl_sec'] ?? null) ? (int) $cacheCfg['lock_ttl_sec'] : 5;
        self::log($logger, 'info', 'APCu cache available');
        return new ApcuCache($apcuPrefix, $lockWaitMs, $lockTtlSec);
    }

    private static function createRedis(array $cacheCfg, ?callable $logger = null): ?CacheBackend
    {
        if (!RedisCache::extensionAvailable()) {
            return null;
        }

        $redisCfg = is_array($cacheCfg['redis'] ?? null) ? $cacheCfg['redis'] : [];
        $host = (string) ($redisCfg['host'] ?? '127.0.0.1');
        $port = is_numeric($redisCfg['port'] ?? null) ? (int) $redisCfg['port'] : 6379;
        $timeout = is_numeric($redisCfg['timeout_sec'] ?? null) ? (float) $redisCfg['timeout_sec'] : 0.2;
        $readTimeout = is_numeric($redisCfg['read_timeout_sec'] ?? null) ? (float) $redisCfg['read_timeout_sec'] : 0.2;
        $db = is_numeric($redisCfg['db'] ?? null) ? (int) $redisCfg['db'] : 0;
        $password = (string) ($redisCfg['password'] ?? '');
        $prefix = (string) ($cacheCfg['prefix'] ?? 'ys:');
        $redisPrefix = (string) ($redisCfg['prefix'] ?? $prefix);
        $lockWaitMs = is_numeric($cacheCfg['lock_wait_ms'] ?? null) ? (int) $cacheCfg['lock_wait_ms'] : 500;
        $lockTtlSec = is_numeric($cacheCfg['lock_ttl_sec'] ?? null) ? (int) $cacheCfg['lock_ttl_sec'] : 5;

        try {
            $redis = new \Redis();
            $connected = $redis->connect($host, $port, $timeout);
            if (!$connected) {
                return null;
            }

            $redis->setOption(\Redis::OPT_READ_TIMEOUT, $readTimeout);
            if ($password !== '') {
                $redis->auth($password);
            }
            if ($db !== 0) {
                $redis->select($db);
            }

            return new RedisCache($redis, $redisPrefix, $lockWaitMs, $lockTtlSec);
        } catch (\Throwable $e) {
            self::log($logger, 'warning', 'Redis cache unavailable: ' . $e->getMessage());
            return null;
        }
    }

    private static function log(?callable $logger, string $level, string $message): void
    {
        if ($logger === null) {
            return;
        }
        $logger($level, $message);
    }
}
