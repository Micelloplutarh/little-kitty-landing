<?php
declare(strict_types=1);

namespace YourShield;

final class FileCache implements CacheBackend
{
    private string $dir;
    private string $prefix;

    public function __construct(string $dir, string $prefix = '')
    {
        $this->prefix = $prefix;
        $this->dir = rtrim(str_replace('\\', '/', $dir), '/');
        $this->ensurePrivateDirectory($this->dir);
        if (random_int(1, 64) === 1) {
            $this->collectExpired(64, 5);
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $path = $this->pathFor($key);
        if (!is_file($path) || is_link($path) || $this->pathHasSymlink($path) || !$this->secureFile($path)) {
            return $default;
        }

        $fp = fopen($path, 'rb');
        if ($fp === false) {
            return $default;
        }

        $shouldDelete = false;
        try {
            if (!flock($fp, LOCK_SH)) {
                return $default;
            }

            $raw = stream_get_contents($fp);
            if (!is_string($raw) || $raw === '') {
                return $default;
            }

            $decoded = json_decode($raw, true);
            if (!is_array($decoded) || !isset($decoded['expires_at'], $decoded['value'])) {
                return $default;
            }

            if ((int) $decoded['expires_at'] <= time()) {
                $shouldDelete = true;
                return $default;
            }

            $value = @unserialize(base64_decode((string) $decoded['value'], true));
            return $value === false && (string) $decoded['value'] !== base64_encode(serialize(false))
                ? $default
                : $value;
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
            if ($shouldDelete) {
                $this->removeExpiredFile($path);
            }
        }
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->write($key, $value, $ttlSeconds, false);
    }

    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        return $this->write($key, $value, $ttlSeconds, true);
    }

    public function delete(string $key): void
    {
        $path = $this->pathFor($key);
        if (is_file($path) && !is_link($path) && !$this->pathHasSymlink($path)) {
            @unlink($path);
        }
    }

    public function mutate(string $key, int $ttlSeconds, callable $updater, mixed $default = null): mixed
    {
        $path = $this->pathFor($key);
        $dir = dirname($path);
        $this->ensurePrivateDirectory($dir);

        $fp = $this->lockPrivateFile($path, $key);

        try {
            rewind($fp);
            $raw = stream_get_contents($fp);
            $current = $default;

            if (is_string($raw) && $raw !== '') {
                $decoded = json_decode($raw, true);
                if (
                    is_array($decoded)
                    && isset($decoded['expires_at'], $decoded['value'])
                    && (int) $decoded['expires_at'] > time()
                ) {
                    $unserialized = @unserialize(base64_decode((string) $decoded['value'], true));
                    if ($unserialized !== false || (string) $decoded['value'] === base64_encode(serialize(false))) {
                        $current = $unserialized;
                    }
                }
            }

            $next = $updater($current);
            $payload = [
                'expires_at' => time() + max(1, $ttlSeconds),
                'value' => base64_encode(serialize($next)),
            ];
            $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
            if (!is_string($encoded)) {
                throw new \RuntimeException('Cannot encode cache payload');
            }

            rewind($fp);
            ftruncate($fp, 0);
            fwrite($fp, $encoded);
            fflush($fp);

            return $next;
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    private function write(string $key, mixed $value, int $ttlSeconds, bool $onlyIfMissing): bool
    {
        $path = $this->pathFor($key);
        $dir = dirname($path);
        $this->ensurePrivateDirectory($dir);

        $fp = $this->lockPrivateFile($path, $key);

        try {
            if ($onlyIfMissing) {
                rewind($fp);
                $raw = stream_get_contents($fp);
                if (is_string($raw) && $raw !== '') {
                    $decoded = json_decode($raw, true);
                    if (is_array($decoded) && isset($decoded['expires_at']) && (int) $decoded['expires_at'] > time()) {
                        return false;
                    }
                }
            }

            $payload = [
                'expires_at' => time() + max(1, $ttlSeconds),
                'value' => base64_encode(serialize($value)),
            ];
            $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
            if (!is_string($encoded)) {
                throw new \RuntimeException('Cannot encode cache payload');
            }

            rewind($fp);
            ftruncate($fp, 0);
            fwrite($fp, $encoded);
            fflush($fp);

            return true;
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    public function collectExpired(int $maxEntries = 0, int $maxMillis = 0): int
    {
        $deadline = $maxMillis > 0 ? microtime(true) + $maxMillis / 1000 : null;
        $startShard = $maxEntries > 0 ? random_int(0, 255) : 0;
        $visited = 0;
        $removed = 0;
        // ponytail: bounded sweeps can revisit live entries; CLI cleanup-cache completes a full pass.
        for ($offset = 0; $offset < 256; $offset++) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                break;
            }
            $shard = $this->dir . '/' . sprintf('%02x', ($startShard + $offset) % 256);
            if (!is_dir($shard) || is_link($shard) || $this->pathHasSymlink($shard)) {
                continue;
            }
            $directory = @opendir($shard);
            if (!is_resource($directory)) {
                continue;
            }
            try {
                while (($name = readdir($directory)) !== false) {
                    if ($name === '.' || $name === '..') {
                        continue;
                    }
                    if (($maxEntries > 0 && $visited >= $maxEntries)
                        || ($deadline !== null && microtime(true) >= $deadline)
                    ) {
                        return $removed;
                    }
                    $visited++;
                    if (preg_match('/\A[a-f0-9]{64}\.cache\z/', $name)
                        && $this->removeExpiredFile($shard . '/' . $name)
                    ) {
                        $removed++;
                    }
                }
            } finally {
                closedir($directory);
            }
        }
        return $removed;
    }

    private function removeExpiredFile(string $path): bool
    {
        if (!is_file($path) || is_link($path) || $this->pathHasSymlink($path)) {
            return false;
        }
        $fp = @fopen($path, 'rb');
        if (!is_resource($fp)) {
            return false;
        }
        try {
            if (!flock($fp, LOCK_EX | LOCK_NB) || !$this->handleMatchesPath($fp, $path)) {
                return false;
            }
            // Cache envelopes always place expires_at first; avoid reading large metric buffers.
            $prefix = fread($fp, 128);
            if (!is_string($prefix) || !preg_match('/\A\{"expires_at":([0-9]+),/', $prefix, $match)
                || (float) $match[1] > time()
            ) {
                return false;
            }
            return @unlink($path);
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    private function lockPrivateFile(string $path, string $key)
    {
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $fp = $this->openPrivateFile($path, $key);
            if (flock($fp, LOCK_EX) && $this->handleMatchesPath($fp, $path)) {
                return $fp;
            }
            flock($fp, LOCK_UN);
            fclose($fp);
        }
        throw new \RuntimeException('Cannot lock current cache key: ' . $key);
    }

    private function handleMatchesPath($fp, string $path): bool
    {
        clearstatcache(true, $path);
        $current = @lstat($path);
        $opened = fstat($fp);
        return is_array($current) && is_array($opened)
            && ($current['mode'] & 0170000) === 0100000
            && $current['dev'] === $opened['dev'] && $current['ino'] === $opened['ino'];
    }

    private function pathFor(string $key): string
    {
        $hash = hash('sha256', $this->prefix . $key);
        $shard = substr($hash, 0, 2);
        return $this->dir . '/' . $shard . '/' . $hash . '.cache';
    }

    private function ensurePrivateDirectory(string $dir): void
    {
        if ($dir === '' || is_link($dir) || $this->pathHasSymlink($dir)) {
            throw new \RuntimeException('Cache directory must not contain symlinks: ' . $dir);
        }
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create cache directory: ' . $dir);
        }
        if (!is_dir($dir) || !is_writable($dir) || !$this->enforcePosixMode($dir, 0700)) {
            throw new \RuntimeException('Cannot secure cache directory: ' . $dir);
        }
    }

    private function openPrivateFile(string $path, string $key)
    {
        if (is_link($path) || $this->pathHasSymlink($path)) {
            throw new \RuntimeException('Cache key path must not contain symlinks: ' . $key);
        }
        $fp = fopen($path, 'c+b');
        if ($fp === false) {
            throw new \RuntimeException('Cannot open cache key: ' . $key);
        }
        if (!$this->secureFile($path) && $this->handleMatchesPath($fp, $path)) {
            fclose($fp);
            throw new \RuntimeException('Cannot secure cache key: ' . $key);
        }
        return $fp;
    }

    private function secureFile(string $path): bool
    {
        return $this->enforcePosixMode($path, 0600);
    }

    private function enforcePosixMode(string $path, int $mode): bool
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            return true;
        }

        clearstatcache(true, $path);
        $permissions = fileperms($path);
        if ($permissions === false) {
            return false;
        }
        if (($permissions & 0777) !== $mode && !@chmod($path, $mode)) {
            return false;
        }
        clearstatcache(true, $path);
        $permissions = fileperms($path);
        return $permissions !== false && ($permissions & 0777) === $mode;
    }

    private function pathHasSymlink(string $path): bool
    {
        $cursor = rtrim(str_replace('\\', '/', $path), '/');
        while ($cursor !== '') {
            if (is_link($cursor)) {
                return true;
            }
            $parent = dirname($cursor);
            if ($parent === $cursor) {
                return false;
            }
            $cursor = $parent;
        }
        return false;
    }
}
