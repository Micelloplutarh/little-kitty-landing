<?php
declare(strict_types=1);

namespace YourShield;

final class MetricsBuffer
{
    private const BUFFER_KEY = 'ys:metrics:buffer';
    private const LAST_FLUSH_KEY = 'ys:metrics:last_flush';
    private const FLUSH_LOCK_KEY = 'ys:metrics:flush_lock';
    private const NEXT_FLUSH_AFTER_KEY = 'ys:metrics:next_flush_after';
    private const FAILURE_COUNT_KEY = 'ys:metrics:failure_count';

    private CacheBackend $cache;
    private CloudClient $cloudClient;
    private RuntimeConfig $config;

    public function __construct(CacheBackend $cache, CloudClient $cloudClient, RuntimeConfig $config)
    {
        $this->cache = $cache;
        $this->cloudClient = $cloudClient;
        $this->config = $config;
    }

    public function recordDecision(string $decision): void
    {
        $this->incrementMetric('decision_' . $decision, 1);
    }

    public function recordCacheHit(string $bucket): void
    {
        $this->incrementMetric('cache_hit_' . $bucket, 1);
    }

    public function recordRateLimit(string $bucket): void
    {
        $this->incrementMetric('rate_limit_' . $bucket, 1);
    }

    public function recordCloudError(string $kind): void
    {
        $this->incrementMetric('cloud_error_' . $kind, 1);
    }

    public function recordLatency(string $bucket): void
    {
        $this->incrementMetric('latency_' . $bucket, 1);
    }

    public function recordSessionDecision(string $sid, string $decision, ?string $path = null): void
    {
        if ($sid === '') {
            return;
        }

        $minute = gmdate('YmdHi');
        $path = $path !== null ? Utils::sanitizePathNoQuery($path) : null;
        $ttl = 86400;

        $this->cache->mutate(self::BUFFER_KEY, $ttl, static function ($current) use ($sid, $decision, $path, $minute): array {
            $buffer = is_array($current) ? $current : [];
            $buffer['site_key'] = $buffer['site_key'] ?? null;
            $buffer['metrics'] = is_array($buffer['metrics'] ?? null) ? $buffer['metrics'] : [];
            $buffer['sessions'] = is_array($buffer['sessions'] ?? null) ? $buffer['sessions'] : [];
            $buffer['updated_at'] = time();

            if (!isset($buffer['sessions'][$sid])) {
                $buffer['sessions'][$sid] = [
                    'sid' => $sid,
                    'pv_total' => 0,
                    'decision_counts' => [],
                    'first_seen_minute' => $minute,
                    'last_seen_minute' => $minute,
                    'first_path' => $path,
                    'last_path' => $path,
                ];
            }

            $session = $buffer['sessions'][$sid];
            $session['pv_total'] = (int) ($session['pv_total'] ?? 0) + 1;
            $session['decision_counts'][$decision] = (int) ($session['decision_counts'][$decision] ?? 0) + 1;
            $session['last_seen_minute'] = $minute;
            if (!isset($session['first_path']) && $path !== null) {
                $session['first_path'] = $path;
            }
            if ($path !== null) {
                $session['last_path'] = $path;
            }
            $buffer['sessions'][$sid] = $session;

            return $buffer;
        }, [
            'site_key' => $this->config->getString('site_key'),
            'metrics' => [],
            'sessions' => [],
            'updated_at' => time(),
        ]);
    }

    public function maybeFlush(): void
    {
        $now = time();
        $interval = max(0, $this->metricInt('flush_interval_sec', $this->config->getInt('metrics_flush_interval_sec', 60)));
        $lastFlush = (int) $this->cache->get(self::LAST_FLUSH_KEY, 0);
        if (($now - $lastFlush) < $interval) {
            return;
        }

        $nextFlushAfter = (int) $this->cache->get(self::NEXT_FLUSH_AFTER_KEY, 0);
        if ($now < $nextFlushAfter) {
            return;
        }

        $lockTtl = max(1, $this->metricInt('flush_lock_ttl_sec', 10));
        if (!$this->cache->add(self::FLUSH_LOCK_KEY, 1, $lockTtl)) {
            return;
        }

        try {
            $buffer = [];
            $this->cache->mutate(
                self::BUFFER_KEY,
                86400,
                function ($current) use (&$buffer): array {
                    $buffer = $this->normalizeBuffer($current);
                    return $this->emptyBuffer();
                },
                $this->emptyBuffer()
            );

            $metrics = $buffer['metrics'];
            $sessions = $buffer['sessions'];
            if ($metrics === [] && $sessions === []) {
                $this->cache->set(self::LAST_FLUSH_KEY, $now, 86400);
                $this->cache->delete(self::NEXT_FLUSH_AFTER_KEY);
                $this->cache->delete(self::FAILURE_COUNT_KEY);
                return;
            }

            $metricsOk = true;
            $sessionsOk = true;
            if ($metrics !== []) {
                try {
                    $result = $this->cloudClient->metricsIngest([
                        'api_ver' => $this->config->getString('api_ver', '1'),
                        'site_key' => $this->config->getString('site_key'),
                        'host' => $_SERVER['HTTP_HOST'] ?? null,
                        'metrics' => $metrics,
                        'emitted_at' => time(),
                    ]);
                    $metricsOk = (bool) ($result['ok'] ?? false);
                } catch (\Throwable) {
                    $metricsOk = false;
                }
            }

            if ($sessions !== []) {
                try {
                    $result = $this->cloudClient->sessionIngest([
                        'api_ver' => $this->config->getString('api_ver', '1'),
                        'site_key' => $this->config->getString('site_key'),
                        'host' => $_SERVER['HTTP_HOST'] ?? null,
                        'sessions' => array_values($sessions),
                        'emitted_at' => time(),
                    ]);
                    $sessionsOk = (bool) ($result['ok'] ?? false);
                } catch (\Throwable) {
                    $sessionsOk = false;
                }
            }

            if ($metricsOk && $sessionsOk) {
                $this->cache->set(self::LAST_FLUSH_KEY, $now, 86400);
                $this->cache->delete(self::NEXT_FLUSH_AFTER_KEY);
                $this->cache->delete(self::FAILURE_COUNT_KEY);
                return;
            }

            $failed = $buffer;
            $failed['metrics'] = $metricsOk ? [] : $metrics;
            $failed['sessions'] = $sessionsOk ? [] : $sessions;
            $this->cache->mutate(
                self::BUFFER_KEY,
                86400,
                fn($current): array => $this->mergeBuffers($failed, $this->normalizeBuffer($current)),
                $this->emptyBuffer()
            );

            $failureCount = (int) $this->cache->get(self::FAILURE_COUNT_KEY, 0) + 1;
            $this->cache->set(self::FAILURE_COUNT_KEY, $failureCount, 86400);

            $baseBackoff = max(1, $this->metricInt('flush_backoff_base_sec', 5));
            $maxBackoff = max($baseBackoff, $this->metricInt('flush_backoff_max_sec', 60));
            $backoff = min($maxBackoff, $baseBackoff * (2 ** min(10, $failureCount - 1)));
            $this->cache->set(self::NEXT_FLUSH_AFTER_KEY, $now + $backoff, 86400);
        } finally {
            $this->cache->delete(self::FLUSH_LOCK_KEY);
        }
    }

    private function incrementMetric(string $name, int $count): void
    {
        $minute = gmdate('YmdHi');
        $metricKey = $minute . ':' . $name;

        $this->cache->mutate(self::BUFFER_KEY, 86400, static function ($current) use ($metricKey, $count): array {
            $buffer = is_array($current) ? $current : [];
            $buffer['site_key'] = $buffer['site_key'] ?? null;
            $buffer['metrics'] = is_array($buffer['metrics'] ?? null) ? $buffer['metrics'] : [];
            $buffer['sessions'] = is_array($buffer['sessions'] ?? null) ? $buffer['sessions'] : [];
            $buffer['updated_at'] = time();

            $buffer['metrics'][$metricKey] = (int) ($buffer['metrics'][$metricKey] ?? 0) + $count;
            return $buffer;
        }, [
            'site_key' => $this->config->getString('site_key'),
            'metrics' => [],
            'sessions' => [],
            'updated_at' => time(),
        ]);
    }

    private function emptyBuffer(): array
    {
        return [
            'site_key' => $this->config->getString('site_key'),
            'metrics' => [],
            'sessions' => [],
            'updated_at' => time(),
        ];
    }

    private function normalizeBuffer(mixed $value): array
    {
        $buffer = is_array($value) ? $value : [];
        return [
            'site_key' => $this->config->getString('site_key'),
            'metrics' => is_array($buffer['metrics'] ?? null) ? $buffer['metrics'] : [],
            'sessions' => is_array($buffer['sessions'] ?? null) ? $buffer['sessions'] : [],
            'updated_at' => (int) ($buffer['updated_at'] ?? time()),
        ];
    }

    private function mergeBuffers(array $older, array $newer): array
    {
        $merged = $newer;
        foreach ($older['metrics'] as $key => $count) {
            $merged['metrics'][$key] = (int) ($merged['metrics'][$key] ?? 0) + (int) $count;
        }

        foreach ($older['sessions'] as $sid => $olderSession) {
            if (!is_array($olderSession)) {
                continue;
            }
            $newerSession = $merged['sessions'][$sid] ?? null;
            if (!is_array($newerSession)) {
                $merged['sessions'][$sid] = $olderSession;
                continue;
            }

            $session = array_replace($olderSession, $newerSession);
            $session['pv_total'] = (int) ($olderSession['pv_total'] ?? 0) + (int) ($newerSession['pv_total'] ?? 0);
            $session['decision_counts'] = is_array($newerSession['decision_counts'] ?? null)
                ? $newerSession['decision_counts']
                : [];
            foreach (is_array($olderSession['decision_counts'] ?? null) ? $olderSession['decision_counts'] : [] as $decision => $count) {
                $session['decision_counts'][$decision] = (int) ($session['decision_counts'][$decision] ?? 0) + (int) $count;
            }

            $olderFirst = (string) ($olderSession['first_seen_minute'] ?? '');
            $newerFirst = (string) ($newerSession['first_seen_minute'] ?? '');
            $session['first_seen_minute'] = $olderFirst === '' || ($newerFirst !== '' && $newerFirst < $olderFirst)
                ? $newerFirst
                : $olderFirst;
            $olderLast = (string) ($olderSession['last_seen_minute'] ?? '');
            $newerLast = (string) ($newerSession['last_seen_minute'] ?? '');
            $session['last_seen_minute'] = $newerLast === '' || ($olderLast !== '' && $olderLast > $newerLast)
                ? $olderLast
                : $newerLast;
            $session['first_path'] = ($olderSession['first_path'] ?? null) ?? ($newerSession['first_path'] ?? null);
            $session['last_path'] = ($newerSession['last_path'] ?? null) ?? ($olderSession['last_path'] ?? null);
            $merged['sessions'][$sid] = $session;
        }

        $merged['site_key'] = $this->config->getString('site_key');
        $merged['updated_at'] = time();
        return $merged;
    }

    private function metricInt(string $key, int $default): int
    {
        $metricsCfg = $this->config->getArray('metrics');
        $value = $metricsCfg[$key] ?? $default;
        return is_numeric($value) ? (int) $value : $default;
    }
}
