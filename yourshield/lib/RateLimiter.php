<?php
declare(strict_types=1);

namespace YourShield;

final class RateLimiter
{
    private CacheBackend $cache;
    private string $prefix;

    public function __construct(CacheBackend $cache, string $prefix = 'ys:rl:')
    {
        $this->cache = $cache;
        $this->prefix = $prefix;
    }

    public function consume(string $key, float $ratePerSec, int $burst, int $tokens = 1): bool
    {
        $rate = max(0.0001, $ratePerSec);
        $burst = max(1, $burst);
        $tokens = max(1, $tokens);
        $now = microtime(true);

        $ttl = max((int) ceil(($burst / $rate) * 2), 60);
        $state = $this->cache->mutate(
            $this->prefix . $key,
            $ttl,
            static function ($current) use ($burst, $tokens, $rate, $now): array {
                $bucket = is_array($current) ? $current : [];
                $available = isset($bucket['tokens']) ? (float) $bucket['tokens'] : (float) $burst;
                $updatedAt = isset($bucket['updated_at']) ? (float) $bucket['updated_at'] : $now;

                $elapsed = max(0.0, $now - $updatedAt);
                $available = min((float) $burst, $available + ($elapsed * $rate));

                $allowed = $available >= $tokens;
                if ($allowed) {
                    $available -= $tokens;
                }

                return [
                    'tokens' => $available,
                    'updated_at' => $now,
                    'allowed' => $allowed,
                ];
            },
            ['tokens' => (float) $burst, 'updated_at' => $now, 'allowed' => true]
        );

        return is_array($state) && (bool) ($state['allowed'] ?? false);
    }
}
