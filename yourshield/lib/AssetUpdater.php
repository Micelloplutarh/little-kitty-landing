<?php
declare(strict_types=1);

namespace YourShield;

final class AssetUpdater
{
    private RuntimeConfig $config;
    private CloudClient $cloudClient;
    private ?\Closure $logger = null;
    private ?\Closure $stagingWriter = null;

    public function __construct(RuntimeConfig $config, CloudClient $cloudClient)
    {
        $this->config = $config;
        $this->cloudClient = $cloudClient;
    }

    public function setLogger(?callable $logger): void
    {
        $this->logger = $logger !== null ? \Closure::fromCallable($logger) : null;
    }

    public function run(): int
    {
        $basePath = trim($this->config->getString('base_path'), '/');
        $publicRoot = rtrim($this->config->getString('public_root', dirname(__DIR__, 2) . '/public'), '/');
        $assetRoot = $publicRoot . '/' . $basePath . '/a';
        $tmpDir = null;
        $lockHandle = null;

        if (!is_dir($assetRoot) && !mkdir($assetRoot, 0775, true) && !is_dir($assetRoot)) {
            $this->log("Cannot create assets root directory: {$assetRoot}", 'error');
            return 1;
        }
        $canonicalAssetRoot = realpath($assetRoot);
        if (!is_string($canonicalAssetRoot) || $canonicalAssetRoot === '') {
            $this->log("Cannot resolve assets root directory: {$assetRoot}", 'error');
            return 1;
        }
        $assetRoot = rtrim(str_replace('\\', '/', $canonicalAssetRoot), '/');

        $lockHandle = $this->acquireLock($assetRoot);
        if (!is_resource($lockHandle)) {
            $this->log('Assets updater is locked by another process', 'error');
            return 1;
        }

        try {
            $assetsCfg = $this->config->getArray('assets');
            $siteHost = Utils::resolveSiteHost($_SERVER, $this->config->getString('site_host'));
            if ($siteHost === '') {
                $this->log('Missing canonical site host for assets updater', 'error');
                return 1;
            }
            $manifestResponse = $this->cloudClient->assetsManifest([
                'api_ver' => $this->config->getString('api_ver', '1'),
                'site_key' => $this->config->getString('site_key'),
                'host' => $siteHost,
                'base_path' => $this->config->getString('base_path'),
            ]);

            if (!$manifestResponse['ok']) {
                $this->log('Failed to fetch assets manifest', 'error');
                return 1;
            }

            $manifest = is_array($manifestResponse['data']) ? $manifestResponse['data'] : [];
            $bundleId = trim((string) ($manifest['bundle_id'] ?? ''));
            if (!$this->isValidBundleId($bundleId)) {
                $this->log('Invalid assets manifest: bundle_id', 'error');
                return 1;
            }

            $files = $this->normalizeManifestFiles($manifest['files'] ?? null);
            if ($files === null || $files === []) {
                $this->log('Invalid assets manifest: files', 'error');
                return 1;
            }

            $targetDir = $assetRoot . '/' . $bundleId;
            $verifySha = $this->assetBool($assetsCfg, 'verify_sha256', true);
            if ($this->bundleLooksReady($targetDir, $files, $verifySha)) {
                $this->log("Bundle already present: {$bundleId}");
            } else {
                $tmpDir = $targetDir . '.tmp.' . Utils::randomToken(8);
                if (!is_dir($tmpDir) && !mkdir($tmpDir, 0775, true) && !is_dir($tmpDir)) {
                    $this->log("Cannot create temp assets directory: {$tmpDir}", 'error');
                    return 1;
                }

                foreach ($files as $file) {
                    $name = $file['name'];
                    $shaExpected = $file['sha256'];

                    $download = $this->cloudClient->assetsBundle([
                        'api_ver' => $this->config->getString('api_ver', '1'),
                        'site_key' => $this->config->getString('site_key'),
                        'host' => $siteHost,
                        'bundle_id' => $bundleId,
                        'file' => $name,
                    ]);

                    if (!$download['ok']) {
                        $this->log("Failed to download bundle file: {$name}", 'error');
                        return 1;
                    }

                    $contentB64 = (string) ($download['data']['content_b64'] ?? '');
                    $content = base64_decode($contentB64, true);
                    if (!is_string($content)) {
                        $this->log("Invalid file content for: {$name}", 'error');
                        return 1;
                    }

                    if ($verifySha && $shaExpected === null) {
                        $this->log("Missing SHA256 for: {$name}", 'error');
                        return 1;
                    }

                    if ($verifySha && $shaExpected !== null) {
                        $actualSha = hash('sha256', $content);
                        if (!hash_equals($shaExpected, $actualSha)) {
                            $this->log("SHA256 mismatch for: {$name}", 'error');
                            return 1;
                        }
                    }

                    $safePath = $this->sanitizeAssetRelativePath($name);
                    if ($safePath === null) {
                        $this->log("Unsafe asset path in manifest: {$name}", 'error');
                        return 1;
                    }

                    $targetFile = $tmpDir . '/' . $safePath;
                    $targetSubdir = dirname($targetFile);
                    if (!is_dir($targetSubdir) && !mkdir($targetSubdir, 0775, true) && !is_dir($targetSubdir)) {
                        $this->log("Cannot create assets subdir for: {$name}", 'error');
                        return 1;
                    }

                    if (!$this->writeVerifiedStagedFile($targetFile, $content)) {
                        $this->log("Cannot write asset file: {$name}", 'error');
                        return 1;
                    }
                    @chmod($targetFile, 0644);
                }

                $manifestToStore = [
                    'bundle_id' => $bundleId,
                    'files' => $files,
                    'updated_at' => time(),
                ];
                $manifestEncoded = json_encode($manifestToStore, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
                if (!is_string($manifestEncoded)
                    || !$this->writeVerifiedStagedFile($tmpDir . '/.bundle-manifest.json', $manifestEncoded)
                ) {
                    $this->log('Cannot write assets bundle manifest', 'error');
                    return 1;
                }

                if (is_link($targetDir) || file_exists($targetDir)) {
                    $this->deleteAssetChild($assetRoot, $targetDir);
                }
                if (
                    !$this->isDirectAssetChild($assetRoot, $tmpDir)
                    || !$this->isDirectAssetChild($assetRoot, $targetDir)
                    || !rename($tmpDir, $targetDir)
                ) {
                    $this->log("Cannot promote temp bundle to target: {$bundleId}", 'error');
                    return 1;
                }
                $tmpDir = null;
            }

            $useSymlinks = $this->assetBool($assetsCfg, 'use_symlinks', DIRECTORY_SEPARATOR !== '\\');
            $previousCurrent = self::activeBundleId($assetRoot);
            $manifestPrev = trim((string) ($manifest['prev_bundle_id'] ?? ''));
            $previousBundle = null;
            if ($this->isValidBundleId($previousCurrent) && $previousCurrent !== $bundleId) {
                $previousBundle = $previousCurrent;
            } elseif ($this->isValidBundleId($manifestPrev) && $manifestPrev !== $bundleId) {
                $previousBundle = $manifestPrev;
            }

            if (!$useSymlinks) {
                $pointer = $assetRoot . '/.current-bundle.json';
                $temporary = $pointer . '.tmp-' . Utils::randomToken(8);
                $json = json_encode(['current' => $bundleId, 'prev' => $previousBundle]);
                if (is_link($pointer) || !is_string($json)
                    || !$this->writeVerifiedStagedFile($temporary, $json)
                    || !@rename($temporary, $pointer)
                ) {
                    @unlink($temporary);
                    $this->log('Unable to activate assets generation pointer.', 'error');
                    return 1;
                }
            }
            if ($useSymlinks && $previousBundle !== null) {
                if (!$this->setSymlink($assetRoot, 'prev', $previousBundle)) {
                    return 1;
                }
            }
            if ($useSymlinks && !$this->setSymlink($assetRoot, 'current', $bundleId)) {
                return 1;
            }
            if ($useSymlinks && is_file($assetRoot . '/.current-bundle.json')
                && !is_link($assetRoot . '/.current-bundle.json')
                && !@unlink($assetRoot . '/.current-bundle.json')
            ) {
                $this->log('Cannot retire the previous assets generation pointer.', 'error');
                return 1;
            }

            $keepBundles = [$bundleId];
            if ($previousBundle !== null) {
                $keepBundles[] = $previousBundle;
            }
            $currentLinkTarget = $this->readSymlinkTarget($assetRoot . '/current');
            $prevLinkTarget = $this->readSymlinkTarget($assetRoot . '/prev');
            if ($this->isValidBundleId($currentLinkTarget)) {
                $keepBundles[] = $currentLinkTarget;
            }
            if ($this->isValidBundleId($prevLinkTarget)) {
                $keepBundles[] = $prevLinkTarget;
            }

            $this->cleanupOldBundles(
                $assetRoot,
                array_values(array_unique($keepBundles)),
                max(1, $this->assetInt($assetsCfg, 'keep_generations', 2))
            );
            $this->log("Assets updated: {$bundleId}");
            return 0;
        } finally {
            if (is_string($tmpDir) && (is_link($tmpDir) || file_exists($tmpDir))) {
                $this->deleteAssetChild($assetRoot, $tmpDir);
            }
            if (is_resource($lockHandle)) {
                flock($lockHandle, LOCK_UN);
                fclose($lockHandle);
            }
        }
    }

    private function acquireLock(string $assetRoot)
    {
        $assetsCfg = $this->config->getArray('assets');
        $lockPath = $assetRoot . '/.updater.lock';
        clearstatcache(true, $lockPath);
        $before = null;
        if (file_exists($lockPath) || is_link($lockPath)) {
            $before = @lstat($lockPath);
            if (!$this->isRegularFileStat($before) || is_link($lockPath)) {
                return null;
            }
        }

        $handle = @fopen($lockPath, 'c+');
        if ($handle === false) {
            return null;
        }
        $opened = @fstat($handle);
        clearstatcache(true, $lockPath);
        $current = @lstat($lockPath);
        if (!$this->isRegularFileStat($opened)
            || !$this->isRegularFileStat($current)
            || !$this->sameFileIdentity($opened, $current)
            || (is_array($before) && !$this->sameFileIdentity($before, $current))
        ) {
            fclose($handle);
            return null;
        }

        $waitMs = max(0, $this->assetInt($assetsCfg, 'updater_lock_wait_ms', 5000));
        $startedAt = microtime(true);

        while (true) {
            if (flock($handle, LOCK_EX | LOCK_NB)) {
                clearstatcache(true, $lockPath);
                $lockedPath = @lstat($lockPath);
                $lockedHandle = @fstat($handle);
                if (!$this->isRegularFileStat($lockedPath)
                    || !$this->isRegularFileStat($lockedHandle)
                    || !$this->sameFileIdentity($lockedHandle, $lockedPath)
                    || !ftruncate($handle, 0)
                ) {
                    flock($handle, LOCK_UN);
                    fclose($handle);
                    return null;
                }
                $meta = json_encode([
                    'pid' => getmypid(),
                    'started_at' => time(),
                    'ttl_sec' => max(30, $this->assetInt($assetsCfg, 'updater_lock_ttl_sec', 120)),
                ], JSON_UNESCAPED_SLASHES);
                if (is_string($meta)) {
                    fwrite($handle, $meta);
                }
                fflush($handle);
                return $handle;
            }

            $elapsedMs = (int) round((microtime(true) - $startedAt) * 1000);
            if ($elapsedMs >= $waitMs) {
                fclose($handle);
                return null;
            }
            usleep(100000);
        }
    }

    private function isRegularFileStat(mixed $stat): bool
    {
        return is_array($stat)
            && isset($stat['mode'])
            && (((int) $stat['mode'] & 0170000) === 0100000);
    }

    private function sameFileIdentity(array $left, array $right): bool
    {
        foreach (['dev', 'ino'] as $key) {
            if (array_key_exists($key, $left)
                && array_key_exists($key, $right)
                && (string) $left[$key] !== (string) $right[$key]
            ) {
                return false;
            }
        }
        return true;
    }

    private function normalizeManifestFiles(mixed $rawFiles): ?array
    {
        if (!is_array($rawFiles)) {
            return null;
        }

        $files = [];
        $seen = [];
        foreach ($rawFiles as $rawFile) {
            $sha = null;
            if (!is_array($rawFile) || !is_string($rawFile['name'] ?? null)) {
                return null;
            }
            $name = trim($rawFile['name']);
            if ($name === '') {
                return null;
            }
            $shaRaw = array_key_exists('sha256', $rawFile)
                ? $rawFile['sha256']
                : ($rawFile['hash'] ?? '');
            if (!is_string($shaRaw)) {
                return null;
            }
            $shaCandidate = strtolower(trim($shaRaw));
            if ($shaCandidate !== '') {
                if (preg_match('/^[a-f0-9]{64}$/', $shaCandidate) !== 1) {
                    return null;
                }
                $sha = $shaCandidate;
            }

            $safePath = $this->sanitizeAssetRelativePath($name);
            if ($safePath === null) {
                return null;
            }
            $lookup = strtolower($safePath);
            if (isset($seen[$lookup])) {
                return null;
            }
            $seen[$lookup] = true;

            $files[] = [
                'name' => $safePath,
                'sha256' => $sha,
            ];
        }

        return $files;
    }

    private function writeVerifiedStagedFile(string $path, string $content): bool
    {
        $written = $this->stagingWriter !== null
            ? ($this->stagingWriter)($path, $content)
            : @file_put_contents($path, $content, LOCK_EX);
        if (!is_int($written) || $written !== strlen($content)) {
            return false;
        }

        $storedSha = @hash_file('sha256', $path);
        return is_string($storedSha) && hash_equals(hash('sha256', $content), strtolower($storedSha));
    }

    private function sanitizeAssetRelativePath(string $path): ?string
    {
        $clean = str_replace('\\', '/', trim($path));
        if (str_starts_with($clean, '/') || preg_match('/^[A-Za-z]:\//', $clean) === 1) {
            return null;
        }
        if ($clean === '' || str_contains($clean, "\0")) {
            return null;
        }

        $parts = explode('/', $clean);
        foreach ($parts as $part) {
            if ($part === '' || $part === '.' || $part === '..') {
                return null;
            }
        }

        return $clean;
    }

    private function bundleLooksReady(string $dir, array $files, bool $verifySha): bool
    {
        if (is_link($dir) || !is_dir($dir)) {
            return false;
        }

        foreach ($files as $file) {
            $path = $dir . '/' . $file['name'];
            if (!is_file($path)) {
                return false;
            }
            if ($verifySha && (!is_string($file['sha256']) || $file['sha256'] === '')) {
                return false;
            }
            if ($verifySha && is_string($file['sha256']) && $file['sha256'] !== '') {
                $actualSha = @hash_file('sha256', $path);
                if (!is_string($actualSha) || !hash_equals($file['sha256'], strtolower($actualSha))) {
                    return false;
                }
            }
        }

        return true;
    }

    private function setSymlink(string $assetRoot, string $linkName, string $target): bool
    {
        $linkPath = $assetRoot . '/' . $linkName;
        if (!$this->isDirectAssetChild($assetRoot, $linkPath) || !$this->isValidBundleId($target)) {
            $this->log("Refusing unsafe assets symlink {$linkName}", 'error');
            return false;
        }

        if (file_exists($linkPath) && !is_link($linkPath)) {
            $this->log("Refusing to replace non-symlink assets path: {$linkPath}", 'error');
            return false;
        }

        $tmpPath = $assetRoot . '/.' . $linkName . '.tmp.' . Utils::randomToken(6);
        if (!@symlink($target, $tmpPath)) {
            $this->log("Unable to create temporary symlink {$tmpPath} -> {$target}", 'error');
            return false;
        }
        if (!@rename($tmpPath, $linkPath)) {
            @unlink($tmpPath);
            $this->log("Unable to create symlink {$linkPath} -> {$target}", 'error');
            return false;
        }
        return true;
    }

    public static function activeBundleId(string $assetRoot): ?string
    {
        $pointer = $assetRoot . '/.current-bundle.json';
        if (is_file($pointer) && !is_link($pointer)) {
            $raw = @file_get_contents($pointer);
            $data = is_string($raw) && strlen($raw) <= 1024 ? json_decode($raw, true) : null;
            $id = is_array($data) ? ($data['current'] ?? null) : null;
        } else {
            $id = is_link($assetRoot . '/current') ? readlink($assetRoot . '/current') : null;
        }
        return is_string($id) && preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}[a-zA-Z0-9]\z/', $id)
            && is_dir($assetRoot . '/' . $id) && !is_link($assetRoot . '/' . $id) ? $id : null;
    }

    private function readSymlinkTarget(string $linkPath): ?string
    {
        if (!is_link($linkPath)) {
            return null;
        }
        $target = readlink($linkPath);
        if (!is_string($target) || $target === '') {
            return null;
        }
        return $target === basename($target) ? $target : null;
    }

    private function cleanupOldBundles(string $assetRoot, array $keepBundles, int $keepGenerations): void
    {
        $keepLookup = array_fill_keys($keepBundles, true);

        $entries = scandir($assetRoot);
        if (!is_array($entries)) {
            return;
        }

        $bundles = [];
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || $entry === 'current' || $entry === 'prev' || $entry[0] === '.') {
                continue;
            }
            $path = $assetRoot . '/' . $entry;
            if (!is_link($path) && is_dir($path) && $this->isValidBundleId($entry)) {
                $bundles[] = [
                    'id' => $entry,
                    'path' => $path,
                    'mtime' => @filemtime($path) ?: 0,
                ];
            }
        }

        usort($bundles, static fn(array $a, array $b): int => $b['mtime'] <=> $a['mtime']);

        $dynamicKeep = [];
        foreach ($bundles as $bundle) {
            if (isset($keepLookup[$bundle['id']])) {
                continue;
            }
            if ((count($keepLookup) + count($dynamicKeep)) >= $keepGenerations) {
                break;
            }
            $dynamicKeep[$bundle['id']] = true;
        }

        $finalKeep = $keepLookup + $dynamicKeep;
        foreach ($bundles as $bundle) {
            if (!isset($finalKeep[$bundle['id']])) {
                $this->deleteAssetChild($assetRoot, $bundle['path']);
            }
        }
    }

    private function isValidBundleId(?string $bundleId): bool
    {
        if (!is_string($bundleId) || $bundleId === '') {
            return false;
        }
        return preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}[a-zA-Z0-9]\z/', $bundleId) === 1;
    }

    private function assetInt(array $assetsCfg, string $key, int $default): int
    {
        $value = $assetsCfg[$key] ?? $default;
        return is_numeric($value) ? (int) $value : $default;
    }

    private function assetBool(array $assetsCfg, string $key, bool $default): bool
    {
        $value = $assetsCfg[$key] ?? $default;
        if (is_bool($value)) {
            return $value;
        }
        if (is_string($value) || is_int($value)) {
            return filter_var((string) $value, FILTER_VALIDATE_BOOLEAN);
        }
        return $default;
    }

    private function isDirectAssetChild(string $assetRoot, string $path): bool
    {
        $root = rtrim(str_replace('\\', '/', $assetRoot), '/');
        $candidate = str_replace('\\', '/', $path);
        $name = basename($candidate);
        return $name !== '.' && $name !== '..' && dirname($candidate) === $root;
    }

    private function deleteAssetChild(string $assetRoot, string $path): void
    {
        if (!$this->isDirectAssetChild($assetRoot, $path)) {
            $this->log("Refusing to delete path outside assets root: {$path}", 'error');
            return;
        }
        $this->deleteDirectory($path);
    }

    private function deleteDirectory(string $dir): void
    {
        if (is_link($dir) || !is_dir($dir)) {
            @unlink($dir);
            return;
        }

        $items = scandir($dir);
        if (!is_array($items)) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (!is_link($path) && is_dir($path)) {
                $this->deleteDirectory($path);
            } else {
                @unlink($path);
            }
        }

        @rmdir($dir);
    }

    private function log(string $message, string $level = 'info'): void
    {
        if ($this->logger !== null) {
            ($this->logger)($level, $message);
            return;
        }

        $line = rtrim($message) . "\n";
        if ($level === 'error' && defined('STDERR')) {
            fwrite(STDERR, $line);
            return;
        }
        if (defined('STDOUT')) {
            fwrite(STDOUT, $line);
            return;
        }
        echo $line;
    }
}
