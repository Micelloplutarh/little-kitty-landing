<?php
declare(strict_types=1);

namespace YourShield;

final class ModuleUpdater
{
    // Bridge-installed before the rest of the release; do not depend on newer Utils APIs here.
    private const BRIDGE_VERSION = '1.0.1-bridge';
    private const BRIDGE_GRACE_SECONDS = 300;
    // autoload precedes management_loader intentionally: its standalone guard blocks legacy
    // Installer loads even if the old per-file updater stops before the next file.
    private const BRIDGE_FILES = [
        'release-required.txt',
        'release_loader.php',
        'lib/Utils.php',
        'lib/AssetUpdater.php',
        'lib/autoload.php',
        'management_loader.php',
        'config.php',
        'lib/ModuleUpdater.php',
        'updater.php',
        'module_updater.php',
        'bootstrap.php',
    ];
    private const RESERVED_PATHS = [
        '.module-current',
        '.module-updater.lock',
        '.release-complete',
        'config.local.php',
        'setup.php',
        '.setup-complete.php',
        '.installer-operation.lock',
        '.validated.json',
    ];
    private const RESERVED_PREFIXES = [
        '.module-releases/',
        '.module-backups/',
        '.installer-backups/',
        'cache/',
    ];

    private RuntimeConfig $config;
    private CloudClient $cloudClient;
    private ?\Closure $logger = null;
    private ?\Closure $stagingWriter = null;
    private bool $validationPending = false;

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
        $this->validationPending = false;
        $moduleRoot = $this->resolveModuleRoot();
        if (!is_dir($moduleRoot) || is_link($moduleRoot)) {
            $this->log("Module root not found: {$moduleRoot}", 'error');
            return 1;
        }

        $lockHandle = $this->acquireLock($moduleRoot);
        if (!is_resource($lockHandle)) {
            $this->log('Module updater is locked by another process', 'error');
            return 1;
        }

        try {
            $cfg = $this->config->getArray('module_update');
            $currentVersion = $this->readCurrentVersion($moduleRoot);
            $bridgeGraceRemaining = $this->bridgeGraceRemaining($moduleRoot, $currentVersion);
            if ($bridgeGraceRemaining > 0) {
                $this->log("Module update deferred for bridge grace ({$bridgeGraceRemaining}s remaining)");
                return 0;
            }

            $channel = trim((string) ($cfg['channel'] ?? 'stable'));
            if ($channel === '') {
                $channel = 'stable';
            }
            $siteHost = $this->resolveSiteHost($_SERVER, $this->config->getString('site_host'));
            if ($siteHost === '') {
                $this->log('Missing canonical site host for module updater', 'error');
                return 1;
            }

            $manifestResponse = $this->cloudClient->moduleManifest([
                'api_ver' => $this->config->getString('api_ver', '1'),
                'site_key' => $this->config->getString('site_key'),
                'host' => $siteHost,
                'current_version' => $currentVersion,
                'channel' => $channel,
            ]);
            if (!$manifestResponse['ok']) {
                $this->log('Failed to fetch module manifest', 'error');
                return 1;
            }

            $manifest = is_array($manifestResponse['data']) ? $manifestResponse['data'] : [];
            $targetVersion = trim((string) ($manifest['version'] ?? ''));
            if ($targetVersion === '') {
                $targetVersion = $currentVersion;
            }
            if (!$this->isValidVersion($targetVersion)) {
                $this->log('Invalid module manifest: version', 'error');
                return 1;
            }
            if ((bool) ($manifest['up_to_date'] ?? false) || $targetVersion === $currentVersion) {
                $this->log("Module is up-to-date ({$currentVersion})");
                return 0;
            }

            $files = $this->normalizeManifestFiles($manifest['files'] ?? null);
            if ($files === null || $files === []) {
                $this->log('Invalid module manifest: files', 'error');
                return 1;
            }

            $verifySha = !array_key_exists('verify_sha256', $cfg) || (bool) $cfg['verify_sha256'];
            if ($targetVersion === self::BRIDGE_VERSION) {
                return $this->installBridge(
                    $moduleRoot,
                    $files,
                    $targetVersion,
                    $currentVersion,
                    $channel,
                    $siteHost,
                    $verifySha,
                    max(1, (int) ($cfg['backup_keep'] ?? 2))
                );
            }

            return $this->installImmutableRelease(
                $moduleRoot,
                $files,
                $targetVersion,
                $currentVersion,
                $channel,
                $siteHost,
                $verifySha
            );
        } finally {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
        }
    }

    public function rollback(): int
    {
        $moduleRoot = $this->resolveModuleRoot();
        if (!is_dir($moduleRoot) || is_link($moduleRoot) || !$this->loadStableReleaseLoader($moduleRoot)) {
            return 1;
        }
        $lock = $this->acquireLock($moduleRoot);
        if (!is_resource($lock)) {
            $this->log('Module updater is locked by another process', 'error');
            return 1;
        }
        try {
            $pointer = $moduleRoot . '/.module-current';
            if (!is_file($pointer) || is_link($pointer) || filesize($pointer) > 1048576) {
                $this->log('No previous immutable module release is available.', 'error');
                return 1;
            }
            $journal = (string) file_get_contents($pointer);
            $current = \ys_last_module_release_id($journal, $moduleRoot);
            foreach (array_reverse(explode("\n", $journal)) as $candidate) {
                if ($candidate === $current || !preg_match('/^r-[a-f0-9]{64}$/D', $candidate)) {
                    continue;
                }
                $releaseRoot = $moduleRoot . '/.module-releases/' . $candidate;
                if (!\ys_module_release_is_complete($releaseRoot, $candidate)) {
                    continue;
                }
                $hashes = [];
                $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($releaseRoot, \FilesystemIterator::SKIP_DOTS));
                foreach ($iterator as $file) {
                    $path = substr($file->getPathname(), strlen($releaseRoot) + 1);
                    if (in_array($path, ['.release-complete', '.validated.json'], true)) {
                        continue;
                    }
                    if ($file->isLink() || !$file->isFile()) {
                        $this->log('Previous release contains an unsafe file.', 'error');
                        return 1;
                    }
                    $hashes[$path] = hash_file('sha256', $file->getPathname());
                }
                ksort($hashes, SORT_STRING);
                $version = trim((string) file_get_contents($releaseRoot . '/version.txt'));
                if (!hash_equals($candidate, $this->buildReleaseId($version, $hashes))) {
                    $this->log('Previous module release has changed; rollback refused.', 'error');
                    return 1;
                }
                if (!$this->activateRelease($moduleRoot, $candidate)) {
                    return 1;
                }
                $this->log('Module rolled back to verified release ' . $version . '.');
                return 0;
            }
            $this->log('No previous immutable module release is available.', 'error');
            return 1;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function installBridge(
        string $moduleRoot,
        array $files,
        string $targetVersion,
        string $currentVersion,
        string $channel,
        string $siteHost,
        bool $verifySha,
        int $backupKeep
    ): int {
        $paths = array_keys($files);
        $expected = self::BRIDGE_FILES;
        sort($paths, SORT_STRING);
        sort($expected, SORT_STRING);
        if ($paths !== $expected) {
            $this->log('Invalid bridge manifest: stable loader/wrappers are incomplete', 'error');
            return 1;
        }

        $backupsRoot = $moduleRoot . '/.module-backups';
        if (!$this->ensureModuleStateDirectory($moduleRoot, '.module-backups', 0770)) {
            $this->log('Module bridge backup root must be a private regular directory', 'error');
            return 1;
        }
        $backupRoot = $backupsRoot . '/' . gmdate('YmdHis') . '_' . $this->randomToken(8);
        $stageRoot = $backupRoot . '/stage';
        if (!@mkdir($backupRoot, 0770) || !@mkdir($stageRoot, 0770)) {
            $this->log('Cannot create module bridge staging directory', 'error');
            $this->deleteDirectory($backupRoot);
            return 1;
        }

        $orderedFiles = [];
        foreach (self::BRIDGE_FILES as $path) {
            $orderedFiles[$path] = $files[$path];
        }
        if ($this->downloadFiles($orderedFiles, $stageRoot, $targetVersion, $siteHost, $verifySha) === null) {
            $this->deleteDirectory($backupRoot);
            return 1;
        }
        if (!$this->writeVerifiedStagedFile($stageRoot . '/version.txt', $targetVersion . "\n")) {
            $this->log('Cannot stage bridge version marker', 'error');
            $this->deleteDirectory($backupRoot);
            return 1;
        }
        @chmod($stageRoot . '/version.txt', 0644);

        $changedPaths = [];
        $activationPaths = array_merge(self::BRIDGE_FILES, ['version.txt']);
        if (!$this->activateBridgeFiles($moduleRoot, $backupRoot, $activationPaths, $changedPaths)) {
            if (!$this->rollbackBridge($moduleRoot, $backupRoot . '/backup', $changedPaths)) {
                $this->log("Bridge rollback incomplete; recovery files retained at {$backupRoot}", 'error');
            }
            $this->deleteDirectory($stageRoot);
            return 1;
        }

        $this->deleteDirectory($stageRoot);
        $this->cleanupBackups($moduleRoot, $backupKeep);
        $this->log("Module bridge installed: {$currentVersion} -> {$targetVersion} ({$channel})");
        return 0;
    }

    private function installImmutableRelease(
        string $moduleRoot,
        array $files,
        string $targetVersion,
        string $currentVersion,
        string $channel,
        string $siteHost,
        bool $verifySha
    ): int {
        if (!$this->loadStableReleaseLoader($moduleRoot)) {
            return 1;
        }
        if (!isset($files['release-required.txt'])) {
            $this->log('Invalid full module manifest: missing release-required.txt', 'error');
            return 1;
        }

        $releasesRoot = $moduleRoot . '/.module-releases';
        if (!$this->ensureModuleStateDirectory($moduleRoot, '.module-releases', 0755)) {
            $this->log('Cannot create immutable module releases directory', 'error');
            return 1;
        }

        $stageRoot = $releasesRoot . '/.stage-' . hash('sha256', $targetVersion . json_encode($files));
        if (is_link($stageRoot) || (!is_dir($stageRoot) && !@mkdir($stageRoot, 0755))) {
            $this->log('Cannot create immutable module staging directory', 'error');
            return 1;
        }

        $actualHashes = $this->downloadFiles($files, $stageRoot, $targetVersion, $siteHost, $verifySha);
        if ($actualHashes === null) {
            if ($this->validationPending) {
                $this->log('Module update staged; repeat the maintenance action to continue native validation.');
                return 2;
            }
            $this->deleteDirectory($stageRoot);
            return 1;
        }

        $versionRaw = @file_get_contents($stageRoot . '/version.txt');
        if (!is_string($versionRaw) || trim($versionRaw) !== $targetVersion) {
            $this->log('Module version marker does not match manifest version', 'error');
            $this->deleteDirectory($stageRoot);
            return 1;
        }

        $releaseId = $this->buildReleaseId($targetVersion, $actualHashes);
        $completePath = $stageRoot . '/.release-complete';
        if (!$this->writeVerifiedStagedFile($completePath, $releaseId . "\n")) {
            $this->log('Cannot write immutable release completion marker', 'error');
            $this->deleteDirectory($stageRoot);
            return 1;
        }
        @chmod($completePath, 0644);
        if (!$this->releaseMatches($stageRoot, $releaseId, $actualHashes)) {
            $this->log('Staged module release is incomplete', 'error');
            $this->deleteDirectory($stageRoot);
            return 1;
        }

        $releaseRoot = $releasesRoot . '/' . $releaseId;
        if (file_exists($releaseRoot)) {
            if (!$this->releaseMatches($releaseRoot, $releaseId, $actualHashes)) {
                $this->log("Immutable release id collision or modified release: {$releaseId}", 'error');
                $this->deleteDirectory($stageRoot);
                return 1;
            }
            $this->deleteDirectory($stageRoot);
        } else {
            if (!@rename($stageRoot, $releaseRoot)) {
                $this->log('Cannot promote immutable module release', 'error');
                $this->deleteDirectory($stageRoot);
                return 1;
            }
        }

        if (!$this->activateRelease($moduleRoot, $releaseId)) {
            return 1;
        }

        $this->log("Module updated: {$currentVersion} -> {$targetVersion} ({$channel}, {$releaseId})");
        return 0;
    }

    private function downloadFiles(
        array $files,
        string $stageRoot,
        string $targetVersion,
        string $siteHost,
        bool $verifySha
    ): ?array {
        $actualHashes = [];
        $downloaded = 0;
        $bounded = PHP_SAPI !== 'cli' && $this->resolvePhpCli($this->config->getString('php_cli')) === null;
        $validationPath = $stageRoot . '/.validated.json';
        if (is_link($validationPath)) {
            return null;
        }
        $validationRaw = is_file($validationPath) ? @file_get_contents($validationPath) : false;
        $validated = is_string($validationRaw) ? json_decode($validationRaw, true) : [];
        $validated = is_array($validated) ? $validated : [];
        foreach ($files as $relative => $file) {
            $existing = $stageRoot . '/' . $relative;
            $cursor = $stageRoot;
            foreach (explode('/', $relative) as $part) {
                $cursor .= '/' . $part;
                if (is_link($cursor)) {
                    return null;
                }
            }
            $expected = $file['sha256'];
            if (is_string($expected) && is_file($existing) && !is_link($existing)
                && hash_equals($expected, (string) @hash_file('sha256', $existing))
            ) {
                if (str_ends_with($relative, '.php') && ($validated[$relative] ?? null) !== $expected
                    && !$this->lintPhpFile($existing)
                ) {
                    return null;
                }
                $actualHashes[$relative] = $expected;
                continue;
            }
            if ($bounded && $downloaded >= 8) {
                $this->validationPending = true;
                return null;
            }
            $downloaded++;
            $download = $this->cloudClient->moduleFile([
                'api_ver' => $this->config->getString('api_ver', '1'),
                'site_key' => $this->config->getString('site_key'),
                'host' => $siteHost,
                'version' => $targetVersion,
                'path' => $relative,
            ]);
            if (!$download['ok']) {
                $this->log("Failed to download module file: {$relative}", 'error');
                return null;
            }

            $content = base64_decode((string) ($download['data']['content_b64'] ?? ''), true);
            if (!is_string($content)) {
                $this->log("Invalid module file content: {$relative}", 'error');
                return null;
            }

            $shaExpected = $file['sha256'];
            $actualSha = hash('sha256', $content);
            if ($verifySha && $shaExpected === null) {
                $this->log("Missing SHA256 for module file: {$relative}", 'error');
                return null;
            }
            if ($verifySha && $shaExpected !== null && !hash_equals($shaExpected, $actualSha)) {
                $this->log("SHA256 mismatch for module file: {$relative}", 'error');
                return null;
            }

            $stagePath = $stageRoot . '/' . $relative;
            if (!$this->createDirectory(dirname($stagePath), 0755)) {
                $this->log("Cannot create staging path for module file: {$relative}", 'error');
                return null;
            }
            if (!$this->writeVerifiedStagedFile($stagePath, $content)) {
                $this->log("Cannot stage module file: {$relative}", 'error');
                return null;
            }
            @chmod($stagePath, 0644);
            if (str_ends_with($relative, '.php') && !$this->lintPhpFile($stagePath)) {
                $this->log("Lint failed for staged module file: {$relative}", 'error');
                return null;
            }
            $validated[$relative] = $actualSha;
            if ($bounded && !$this->writeVerifiedStagedFile($validationPath, (string) json_encode($validated))) {
                return null;
            }
            $actualHashes[$relative] = $actualSha;
        }

        ksort($actualHashes, SORT_STRING);
        return $actualHashes;
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

    private function buildReleaseId(string $targetVersion, array $actualHashes): string
    {
        $hash = hash_init('sha256');
        hash_update($hash, "yourshield-release-v1\0{$targetVersion}\0");
        foreach ($actualHashes as $path => $sha256) {
            hash_update($hash, $path . "\0" . $sha256 . "\0");
        }
        return 'r-' . hash_final($hash);
    }

    private function releaseMatches(string $releaseRoot, string $releaseId, array $actualHashes): bool
    {
        if (!\ys_module_release_is_complete($releaseRoot, $releaseId)) {
            return false;
        }
        foreach ($actualHashes as $path => $expectedSha) {
            $filePath = $releaseRoot . '/' . $path;
            if (!is_file($filePath) || is_link($filePath)) {
                return false;
            }
            $actualSha = @hash_file('sha256', $filePath);
            if (!is_string($actualSha) || !hash_equals($expectedSha, $actualSha)) {
                return false;
            }
        }
        return true;
    }

    private function activateRelease(string $moduleRoot, string $releaseId): bool
    {
        if (!$this->loadStableReleaseLoader($moduleRoot)) {
            return false;
        }

        $pointerPath = $moduleRoot . '/.module-current';
        $pointer = $this->openVerifiedRegularFile($pointerPath, 0022);
        if (!is_resource($pointer)) {
            $this->log('Module release pointer must be a regular file', 'error');
            return false;
        }
        if (!flock($pointer, LOCK_EX)) {
            fclose($pointer);
            $this->log('Cannot lock module release pointer', 'error');
            return false;
        }

        $ok = false;
        try {
            if (!$this->regularFileHandleMatchesPath($pointer, $pointerPath)) {
                $this->log('Module release pointer changed while acquiring its lock', 'error');
                return false;
            }
            rewind($pointer);
            $journal = stream_get_contents($pointer);
            if (!is_string($journal)) {
                $this->log('Cannot read module release pointer', 'error');
                return false;
            }
            $oldReleaseId = \ys_last_module_release_id($journal, $moduleRoot);
            $stat = fstat($pointer);
            $originalSize = is_array($stat) ? (int) ($stat['size'] ?? strlen($journal)) : strlen($journal);

            if (fseek($pointer, 0, SEEK_END) !== 0
                || !$this->writeAll($pointer, "\n{$releaseId}\n")
                || !fflush($pointer)
            ) {
                @ftruncate($pointer, $originalSize);
                @fflush($pointer);
                $this->log('Cannot append module release pointer', 'error');
                return false;
            }
            if (function_exists('fsync') && !@fsync($pointer)) {
                $this->log('Module release pointer fsync failed; complete journal fallback remains valid', 'warning');
            }

            rewind($pointer);
            $updatedJournal = stream_get_contents($pointer);
            $selected = is_string($updatedJournal)
                ? \ys_last_module_release_id($updatedJournal, $moduleRoot)
                : null;
            if ($selected !== $releaseId) {
                if ($oldReleaseId !== null && fseek($pointer, 0, SEEK_END) === 0) {
                    $this->writeAll($pointer, "\n{$oldReleaseId}\n");
                    @fflush($pointer);
                    if (function_exists('fsync')) {
                        @fsync($pointer);
                    }
                } else {
                    @ftruncate($pointer, $originalSize);
                    @fflush($pointer);
                }
                $this->log('Module release pointer verification failed', 'error');
                return false;
            }

            $ok = true;
            return true;
        } finally {
            flock($pointer, LOCK_UN);
            fclose($pointer);
            if (!$ok) {
                clearstatcache(true, $pointerPath);
            }
        }
    }

    private function loadStableReleaseLoader(string $moduleRoot): bool
    {
        $loaderPath = $moduleRoot . '/release_loader.php';
        if (!is_file($loaderPath) || is_link($loaderPath)) {
            $this->log('Stable module release loader is missing', 'error');
            return false;
        }
        require_once $loaderPath;
        if (!function_exists('ys_last_module_release_id')
            || !function_exists('ys_module_release_is_complete')
        ) {
            $this->log('Stable module release loader is invalid', 'error');
            return false;
        }
        return true;
    }

    private function writeAll($handle, string $content): bool
    {
        $offset = 0;
        $length = strlen($content);
        while ($offset < $length) {
            $written = @fwrite($handle, substr($content, $offset));
            if (!is_int($written) || $written <= 0) {
                return false;
            }
            $offset += $written;
        }
        return true;
    }

    private function activateBridgeFiles(
        string $moduleRoot,
        string $backupRoot,
        array $stagedPaths,
        array &$changedPaths
    ): bool {
        $stageRoot = $backupRoot . '/stage';
        $backupFilesRoot = $backupRoot . '/backup';
        foreach ($stagedPaths as $relative) {
            $stagePath = $stageRoot . '/' . $relative;
            if (!is_file($stagePath)) {
                $this->log("Staged bridge file is missing: {$relative}", 'error');
                return false;
            }

            $targetPath = $moduleRoot . '/' . $relative;
            if ((file_exists($targetPath) || is_link($targetPath))
                && (is_link($targetPath) || !is_file($targetPath))
            ) {
                $this->log("Bridge target must be a regular file: {$relative}", 'error');
                return false;
            }
            if (!$this->createDirectory(dirname($targetPath), 0755)) {
                $this->log("Cannot create bridge target directory: {$relative}", 'error');
                return false;
            }
            $backupPath = $backupFilesRoot . '/' . $relative;
            if (!$this->createDirectory(dirname($backupPath), 0770)) {
                $this->log("Cannot create bridge backup path: {$relative}", 'error');
                return false;
            }
            if (is_file($targetPath) && !copy($targetPath, $backupPath)) {
                $this->log("Cannot backup bridge file: {$relative}", 'error');
                return false;
            }

            if (!$this->replaceRegularFile($stagePath, $targetPath)) {
                $this->log("Cannot promote bridge file: {$relative}", 'error');
                return false;
            }
            $changedPaths[] = $relative;
        }
        return true;
    }

    private function rollbackBridge(string $moduleRoot, string $backupRoot, array $changedPaths): bool
    {
        $ok = true;
        for ($i = count($changedPaths) - 1; $i >= 0; $i--) {
            $relative = $changedPaths[$i];
            $target = $moduleRoot . '/' . $relative;
            $backup = $backupRoot . '/' . $relative;
            if (is_file($backup)) {
                if ((file_exists($target) || is_link($target))
                    && (is_link($target) || !is_file($target))
                ) {
                    $this->log("Cannot restore non-regular bridge target: {$relative}", 'error');
                    $ok = false;
                    continue;
                }
                if (!$this->replaceRegularFile($backup, $target)) {
                    $this->log("Cannot restore bridge backup: {$relative}", 'error');
                    $ok = false;
                }
                continue;
            }

            if (is_link($target) || (file_exists($target) && !is_file($target))) {
                $this->log("Cannot remove non-regular bridge target: {$relative}", 'error');
                $ok = false;
            } elseif (is_file($target) && !@unlink($target)) {
                $this->log("Cannot remove newly-created bridge target: {$relative}", 'error');
                $ok = false;
            }
        }
        return $ok;
    }

    private function replaceRegularFile(string $source, string $target): bool
    {
        $tmpPath = $target . '.tmp.' . $this->randomToken(8);
        if (!copy($source, $tmpPath)) {
            @unlink($tmpPath);
            return false;
        }
        @chmod($tmpPath, 0644);
        if (!@rename($tmpPath, $target)) {
            @unlink($tmpPath);
            return false;
        }
        return true;
    }

    private function resolveModuleRoot(): string
    {
        if (defined('YS_MODULE_ROOT') && is_string(constant('YS_MODULE_ROOT'))) {
            return rtrim((string) constant('YS_MODULE_ROOT'), '/\\');
        }
        $projectRoot = rtrim($this->config->getString('project_root', dirname(__DIR__, 2)), '/\\');
        return $projectRoot . '/yourshield';
    }

    private function acquireLock(string $moduleRoot)
    {
        $cfg = $this->config->getArray('module_update');
        $waitMs = max(0, is_numeric($cfg['lock_wait_ms'] ?? null) ? (int) $cfg['lock_wait_ms'] : 3000);
        $lockPath = $moduleRoot . '/.module-updater.lock';
        $handle = $this->openVerifiedRegularFile($lockPath, 0077);
        if (!is_resource($handle)) {
            return null;
        }

        $startedAt = microtime(true);
        while (true) {
            if (flock($handle, LOCK_EX | LOCK_NB)) {
                if (!$this->regularFileHandleMatchesPath($handle, $lockPath)
                    || !ftruncate($handle, 0)
                ) {
                    flock($handle, LOCK_UN);
                    fclose($handle);
                    return null;
                }
                $meta = json_encode(['pid' => getmypid(), 'started_at' => time()], JSON_UNESCAPED_SLASHES);
                if (is_string($meta)) {
                    fwrite($handle, $meta);
                }
                fflush($handle);
                return $handle;
            }
            if ((int) round((microtime(true) - $startedAt) * 1000) >= $waitMs) {
                fclose($handle);
                return null;
            }
            usleep(100000);
        }
    }

    /**
     * Open a path without mutating it until its regular-file identity is proven.
     *
     * @return resource|null
     */
    private function openVerifiedRegularFile(string $path, int $createMask)
    {
        clearstatcache(true, $path);
        $before = null;
        if (file_exists($path) || is_link($path)) {
            $before = @lstat($path);
            if (!$this->isRegularFileStat($before) || is_link($path)) {
                return null;
            }
        }

        $previousMask = null;
        if ($before === null && DIRECTORY_SEPARATOR !== '\\') {
            $previousMask = umask($createMask);
        }
        try {
            // Exclusive creation cannot follow a link introduced after the absent-path check.
            $handle = @fopen($path, $before === null ? 'x+b' : 'r+b');
        } finally {
            if (is_int($previousMask)) {
                umask($previousMask);
            }
        }
        if (!is_resource($handle)) {
            return null;
        }
        if (!$this->regularFileHandleMatchesPath($handle, $path, $before)) {
            fclose($handle);
            return null;
        }
        return $handle;
    }

    private function regularFileHandleMatchesPath($handle, string $path, mixed $expectedPathStat = null): bool
    {
        $handleStat = @fstat($handle);
        clearstatcache(true, $path);
        $pathStat = @lstat($path);
        return $this->isRegularFileStat($handleStat)
            && $this->isRegularFileStat($pathStat)
            && $this->sameFileIdentity($handleStat, $pathStat)
            && (!is_array($expectedPathStat) || $this->sameFileIdentity($expectedPathStat, $pathStat));
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
            if (!array_key_exists($key, $left)
                || !array_key_exists($key, $right)
                || (string) $left[$key] !== (string) $right[$key]
            ) {
                return false;
            }
        }
        return true;
    }

    private function bridgeGraceRemaining(string $moduleRoot, string $currentVersion): int
    {
        if ($currentVersion !== self::BRIDGE_VERSION) {
            return 0;
        }
        $versionPath = $moduleRoot . '/version.txt';
        clearstatcache(true, $versionPath);
        $modifiedAt = @filemtime($versionPath);
        if (!is_int($modifiedAt)) {
            return self::BRIDGE_GRACE_SECONDS;
        }
        return max(0, $modifiedAt + self::BRIDGE_GRACE_SECONDS - time());
    }

    private function readCurrentVersion(string $moduleRoot): string
    {
        $releaseRoot = null;
        if (defined('YS_RELEASE_ROOT') && is_string(constant('YS_RELEASE_ROOT'))) {
            $candidate = rtrim((string) constant('YS_RELEASE_ROOT'), '/\\');
            if ($candidate === $moduleRoot || str_starts_with($candidate, $moduleRoot . '/.module-releases/')) {
                $releaseRoot = $candidate;
            }
        }
        if ($releaseRoot === null) {
            $loaderPath = $moduleRoot . '/release_loader.php';
            if (is_file($loaderPath)) {
                require_once $loaderPath;
                if (function_exists('ys_resolve_module_release_root')) {
                    $releaseRoot = \ys_resolve_module_release_root($moduleRoot);
                }
            }
        }
        if ($releaseRoot === null) {
            $releaseRoot = $moduleRoot;
        }

        $version = $this->readVersionFile($releaseRoot . '/version.txt');
        if ($version !== '') {
            return $version;
        }
        $cfgVersion = trim($this->config->getString('module_version', ''));
        return $cfgVersion !== '' ? $cfgVersion : '0.0.0';
    }

    private function readVersionFile(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }
        $raw = @file_get_contents($path);
        return is_string($raw) ? trim($raw) : '';
    }

    private function isValidVersion(string $version): bool
    {
        return (bool) preg_match('/\A[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\z/', $version);
    }

    private function normalizeManifestFiles(mixed $rawFiles): ?array
    {
        if (!is_array($rawFiles)) {
            return null;
        }
        $files = [];
        $caseFoldedPaths = [];
        foreach ($rawFiles as $raw) {
            if (!is_array($raw)) {
                return null;
            }
            $path = trim((string) ($raw['path'] ?? ($raw['name'] ?? '')));
            $safePath = $this->sanitizeModuleRelativePath($path);
            if ($safePath === null) {
                return null;
            }
            $folded = strtolower($safePath);
            if (isset($caseFoldedPaths[$folded])) {
                return null;
            }
            $caseFoldedPaths[$folded] = true;

            $shaRaw = strtolower(trim((string) ($raw['sha256'] ?? '')));
            if ($shaRaw !== '' && !preg_match('/\A[a-f0-9]{64}\z/', $shaRaw)) {
                return null;
            }
            $files[$safePath] = ['path' => $safePath, 'sha256' => $shaRaw !== '' ? $shaRaw : null];
        }
        ksort($files, SORT_STRING);
        return $files;
    }

    private function sanitizeModuleRelativePath(string $path): ?string
    {
        $clean = str_replace('\\', '/', trim($path));
        $clean = ltrim($clean, '/');
        if ($clean === '' || preg_match('/[\x00-\x1F\x7F:]/', $clean)) {
            return null;
        }
        foreach (explode('/', $clean) as $part) {
            if ($part === '' || $part === '.' || $part === '..') {
                return null;
            }
        }

        $folded = strtolower($clean);
        if (in_array($folded, self::RESERVED_PATHS, true)) {
            return null;
        }
        foreach (self::RESERVED_PREFIXES as $prefix) {
            if (str_starts_with($folded, $prefix)) {
                return null;
            }
        }
        return $clean;
    }

    private function createDirectory(string $path, int $mode): bool
    {
        if (is_dir($path) && !is_link($path)) {
            return true;
        }
        if (file_exists($path) || is_link($path)) {
            return false;
        }
        return @mkdir($path, $mode, true) || (is_dir($path) && !is_link($path));
    }

    private function ensureModuleStateDirectory(string $moduleRoot, string $name, int $mode): bool
    {
        if (!preg_match('/\A\.[a-z0-9-]+\z/', $name)) {
            return false;
        }
        $path = $moduleRoot . '/' . $name;
        if (is_link($path) || (file_exists($path) && !is_dir($path))) {
            return false;
        }
        if (!is_dir($path) && !@mkdir($path, $mode)) {
            return false;
        }
        @chmod($path, $mode);
        return is_dir($path) && !is_link($path);
    }

    private function cleanupBackups(string $moduleRoot, int $keep): void
    {
        $root = $moduleRoot . '/.module-backups';
        if (!is_dir($root) || is_link($root)) {
            return;
        }
        $entries = scandir($root);
        if (!is_array($entries)) {
            return;
        }
        $dirs = [];
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $root . '/' . $entry;
            if (is_dir($path) && !is_link($path)) {
                $dirs[] = $path;
            }
        }
        rsort($dirs, SORT_STRING);
        for ($i = $keep; $i < count($dirs); $i++) {
            $this->deleteDirectory($dirs[$i]);
        }
    }

    private function deleteDirectory(string $dir): void
    {
        if (!is_dir($dir) || is_link($dir)) {
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
            if (is_dir($path) && !is_link($path)) {
                $this->deleteDirectory($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    private function lintPhpFile(string $path): bool
    {
        $php = $this->resolvePhpCli($this->config->getString('php_cli'));
        if ($php === null) {
            return $this->lintWithNativeValidator($path);
        }
        try {
            $output = [];
            $code = 1;
            @exec($this->buildPhpCliCommand($php, ['-l', $path]), $output, $code);
            return $code === 0;
        } catch (\Throwable) {
            return false;
        }
    }

    private function resolvePhpCli(string $configured): ?string
    {
        if (!$this->canUseExec()) {
            return null;
        }
        $candidates = [
            $configured,
            defined('PHP_BINDIR') ? PHP_BINDIR . '/php' : '',
            defined('PHP_BINARY') && is_string(PHP_BINARY) ? PHP_BINARY : '',
            '/usr/bin/php',
            '/usr/local/bin/php',
            'php',
        ];
        foreach (array_unique(array_filter(array_map('trim', $candidates))) as $candidate) {
            $name = strtolower(basename($candidate));
            if (str_contains($name, 'fpm') || str_contains($name, 'cgi')) {
                continue;
            }
            try {
                $output = [];
                $code = 1;
                @exec($this->buildPhpCliCommand(
                    $candidate,
                    ['-r', 'exit(PHP_SAPI === "cli" ? 0 : 1);']
                ), $output, $code);
                if ($code === 0) {
                    return $candidate;
                }
            } catch (\Throwable) {
                return null;
            }
        }
        return null;
    }

    private function lintWithNativeValidator(string $path): bool
    {
        $cfg = $this->config->getArray('module_update');
        $url = (string) ($cfg['validator_url'] ?? '');
        $token = (string) ($cfg['validator_token'] ?? '');
        $host = $this->canonicalHost((string) parse_url($url, PHP_URL_HOST));
        $siteHost = $this->canonicalHost($this->config->getString('site_host'));
        $root = $this->resolveModuleRoot();
        $relative = str_starts_with($path, $root . '/') ? substr($path, strlen($root) + 1) : '';
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if ($host === '' || $host !== $siteHost || strlen($token) < 32
            || !in_array($scheme, ['https', 'http'], true)
            || parse_url($url, PHP_URL_USER) !== null || parse_url($url, PHP_URL_FRAGMENT) !== null
            || parse_url($url, PHP_URL_QUERY) !== null
            || parse_url($url, PHP_URL_PATH) !== rtrim($this->config->getString('mount_path'), '/') . '/ys-validate.php'
            || !str_starts_with($relative, '.module-releases/.stage-')
        ) {
            $this->log('PHP CLI unavailable; configure verified native validation or deliver a complete package manually.', 'error');
            return false;
        }
        $sha = @hash_file('sha256', $path);
        if (!is_string($sha)) {
            return false;
        }
        $body = json_encode(['path' => $relative, 'sha256' => $sha]);
        if (!is_string($body)) {
            return false;
        }
        $response = (new HttpClient())->request('POST', $url,
            ['Content-Type: application/json', 'X-YourShield-Validator: ' . $token], $body, 1000, 5000, 4096);
        $data = json_decode((string) ($response['body'] ?? ''), true);
        return (int) ($response['status'] ?? 0) === 200 && is_array($data)
            && ($data['ok'] ?? false) === true && hash_equals($sha, (string) ($data['sha256'] ?? ''))
            && hash_equals($sha, (string) @hash_file('sha256', $path));
    }

    private function buildPhpCliCommand(string $binary, array $arguments, ?bool $windows = null): string
    {
        $parts = [escapeshellarg($binary)];
        foreach ($arguments as $argument) {
            $parts[] = escapeshellarg((string) $argument);
        }
        $discard = ($windows ?? DIRECTORY_SEPARATOR === '\\') ? 'NUL' : '/dev/null';
        return implode(' ', $parts) . ' >' . $discard . ' 2>&1';
    }

    private function canUseExec(): bool
    {
        if (!function_exists('exec')) {
            return false;
        }
        $disabled = strtolower((string) ini_get('disable_functions'));
        return $disabled === '' || !in_array('exec', array_map('trim', explode(',', $disabled)), true);
    }

    private function resolveSiteHost(array $server, string $configured): string
    {
        $environment = (string) (getenv('YS_SITE_HOST') ?: '');
        foreach ([$server['HTTP_HOST'] ?? '', $configured, $environment, $server['SERVER_NAME'] ?? ''] as $candidate) {
            $host = $this->canonicalHost(is_string($candidate) ? $candidate : '');
            if ($host !== '') {
                return $host;
            }
        }
        return '';
    }

    private function canonicalHost(string $raw): string
    {
        $host = strtolower(trim($raw));
        if ($host === '' || str_contains($host, "\0") || preg_match('~[\\s/@?#]~', $host)) {
            return '';
        }
        if ($host[0] === '[') {
            if (!preg_match('/^\[([^]]+)](?::([0-9]{1,5}))?$/', $host, $match)) {
                return '';
            }
            if (isset($match[2]) && ((int) $match[2] < 1 || (int) $match[2] > 65535)) {
                return '';
            }
            return filter_var($match[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? $match[1] : '';
        }
        if (substr_count($host, ':') === 1) {
            [$candidate, $port] = explode(':', $host, 2);
            if ($port === '' || !ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
                return '';
            }
            $host = $candidate;
        } elseif (str_contains($host, ':')) {
            return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? $host : '';
        }
        $host = rtrim($host, '.');
        if ($host === '' || strlen($host) > 253) {
            return '';
        }
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $host;
        }
        return preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $host)
            ? $host
            : '';
    }

    private function randomToken(int $length): string
    {
        $bytes = random_bytes((int) ceil($length * 0.75));
        $token = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        return substr($token, 0, $length);
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
