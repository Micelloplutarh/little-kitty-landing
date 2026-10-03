<?php
declare(strict_types=1);

namespace YourShield;

final class RuntimeConfig
{
    private array $data;

    public function __construct(array $data)
    {
        $this->data = $data;
        // Legacy web-installer entrypoints also read this flag after an immutable upgrade.
        $webInstaller = $this->getArray('web_installer');
        $webInstaller['allow_local_without_token'] = false;
        $this->data['web_installer'] = $webInstaller;

        if (!isset($this->data['base_path']) || !is_string($this->data['base_path'])) {
            throw new \InvalidArgumentException('Missing required config key: base_path');
        }

        $base = '/' . ltrim($this->data['base_path'], '/');
        $base = rtrim($base, '/');
        $this->data['base_path'] = $base === '' ? '/' : $base;

        $moduleRoot = defined('YS_MODULE_ROOT') && is_string(constant('YS_MODULE_ROOT'))
            ? rtrim((string) constant('YS_MODULE_ROOT'), '/\\')
            : dirname(__DIR__);
        $projectRoot = $this->getString('project_root', dirname($moduleRoot));
        $autoRuntimeDir = rtrim(sys_get_temp_dir(), '/\\')
            . '/.yourshield-runtime-'
            . substr(hash('sha256', str_replace('\\', '/', $projectRoot)), 0, 16);
        $runtimePath = self::normalizePath($this->getString('runtime_dir', $autoRuntimeDir));
        $cachePath = self::normalizePath($this->getString('cache_dir', $runtimePath . '/cache'));
        self::assertPrivateStoragePath($runtimePath, 'runtime_dir');
        self::assertPrivateStoragePath($cachePath, 'cache_dir');
        $runtimeDir = Utils::canonicalAbsolutePath($runtimePath);
        $cacheDir = Utils::canonicalAbsolutePath($cachePath);
        if ($runtimeDir === null || $cacheDir === null) {
            throw new \InvalidArgumentException('Runtime storage path could not be canonicalized');
        }

        $publicPath = self::normalizePath($this->getString('public_root'));
        $publicRoot = $publicPath === '' ? null : Utils::canonicalAbsolutePath($publicPath);
        if ($publicPath !== '' && $publicRoot === null) {
            throw new \InvalidArgumentException('public_root must be an absolute canonical path');
        }
        if ($publicRoot !== null && (
            Utils::pathIsInside($publicRoot, $runtimeDir)
            || Utils::pathIsInside($runtimeDir, $publicRoot)
            || Utils::pathIsInside($publicRoot, $cacheDir)
            || Utils::pathIsInside($cacheDir, $publicRoot)
        )) {
            throw new \InvalidArgumentException('Runtime storage must stay outside public_root');
        }

        $this->data['runtime_dir'] = $runtimeDir;
        $this->data['cache_dir'] = $cacheDir;
    }

    public function cacheNamespace(): string
    {
        $identity = [
            $this->getString('site_key'),
            $this->getString('project_root', dirname($this->getString('cache_dir'))),
            $this->getString('public_root'),
            $this->getString('base_path'),
        ];
        return 's-' . hash('sha256', serialize($identity)) . ':';
    }

    public function pathPrefixes(string $key, CacheBackend $cache): array
    {
        $bundle = $cache->get('ys:policy_bundle', null);
        if (is_array($bundle)) {
            $storedAt = (int) ($bundle['stored_at'] ?? 0);
            $ttl = (int) ($bundle['ttl'] ?? 0);
            $now = time();
            if ($storedAt <= 0 || $ttl <= 0 || $storedAt > $now
                || $ttl > PHP_INT_MAX - $storedAt || $storedAt + $ttl <= $now
            ) {
                $cache->delete('ys:policy_bundle');
                $bundle = null;
            }
        }
        $prefixes = array_merge($this->getArray($key), is_array($bundle[$key] ?? null) ? $bundle[$key] : []);
        $result = [];
        foreach ($prefixes as $prefix) {
            if (is_string($prefix) && trim($prefix) !== '') {
                $result[] = rtrim('/' . ltrim(trim($prefix), '/'), '/') ?: '/';
            }
        }
        return array_values(array_unique($result));
    }

    public function shouldFailOpen(string $path, CacheBackend $cache): bool
    {
        $mode = strtolower($this->getString('fail_mode', 'hybrid'));
        if ($mode === 'fail-open') {
            return true;
        }
        if ($mode === 'fail-close') {
            return false;
        }
        foreach ($this->pathPrefixes('strict_path_prefixes', $cache) as $prefix) {
            if (Utils::pathMatchesPrefix($path, $prefix)) {
                return false;
            }
        }
        return true;
    }

    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new \RuntimeException('Config file not found: ' . $path);
        }

        $config = require $path;
        if (!is_array($config)) {
            throw new \RuntimeException('Config file must return array: ' . $path);
        }

        return new self($config);
    }

    public function all(): array
    {
        return $this->data;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function getString(string $key, string $default = ''): string
    {
        $value = $this->get($key, $default);
        if (!is_string($value)) {
            return $default;
        }
        return $value;
    }

    public function getInt(string $key, int $default = 0): int
    {
        $value = $this->get($key, $default);
        return is_numeric($value) ? (int) $value : $default;
    }

    public function getBool(string $key, bool $default = false): bool
    {
        $value = $this->get($key, $default);
        if (is_bool($value)) {
            return $value;
        }
        if (is_string($value) || is_int($value)) {
            return filter_var((string) $value, FILTER_VALIDATE_BOOLEAN);
        }
        return $default;
    }

    public function getArray(string $key, array $default = []): array
    {
        $value = $this->get($key, $default);
        return is_array($value) ? $value : $default;
    }

    private static function assertPrivateStoragePath(string $path, string $key): void
    {
        if ($path === '' || !self::isAbsolutePath($path)) {
            throw new \InvalidArgumentException("{$key} must be an absolute path");
        }
        if ($path === '/' || preg_match('/^[A-Za-z]:[\\\\\/]?$/', $path) === 1) {
            throw new \InvalidArgumentException("{$key} must not be a filesystem root");
        }
        foreach (explode('/', str_replace('\\', '/', $path)) as $segment) {
            if ($segment === '.' || $segment === '..') {
                throw new \InvalidArgumentException("{$key} must not contain dot segments");
            }
        }
        if (self::pathHasSymlink($path)) {
            throw new \RuntimeException("{$key} must not contain symlinks");
        }
    }

    private static function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/') || preg_match('/^[A-Za-z]:[\\\\\/]/', $path) === 1;
    }

    private static function normalizePath(string $path): string
    {
        $path = str_replace('\\', '/', trim($path));
        if ($path === '/' || preg_match('/^[A-Za-z]:\/$/', $path) === 1) {
            return $path;
        }
        return rtrim($path, '/');
    }

    private static function pathHasSymlink(string $path): bool
    {
        $cursor = self::normalizePath($path);
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
