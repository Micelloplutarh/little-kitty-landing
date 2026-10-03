<?php
declare(strict_types=1);

namespace YourShield;

final class Installer
{
    private const MARKER_START = '// YOURSHIELD-BOOTSTRAP-START';
    private const MARKER_END = '// YOURSHIELD-BOOTSTRAP-END';
    private const HTACCESS_MARKER_START = '# YOURSHIELD-ROUTER-START';
    private const HTACCESS_MARKER_END = '# YOURSHIELD-ROUTER-END';
    private const CDN_PROVIDERS = ['none', 'cloudflare', 'cloudfront', 'fastly'];
    private const RUNTIME_ENVIRONMENTS = ['apache', 'litespeed', 'nginx', 'iis', 'caddy', 'php_builtin', 'unknown'];
    private const RUNTIME_HTACCESS_SUPPORTED = ['apache', 'litespeed'];
    private const RUNTIME_HTACCESS_UNSUPPORTED = ['nginx', 'iis', 'caddy', 'php_builtin'];
    private const BOT_BLOCK_MODES = ['block', 'whitepage_dir'];
    private const CACHE_DRIVERS = ['auto', 'file', 'apcu', 'redis'];

    private string $projectRoot;
    private string $yourShieldDir;
    private string $configPath;
    private string $configLocalPath;
    private string $bootstrapPath;
    private string $backupDir;
    private ?\Closure $logger = null;
    private ?\Closure $configWriter = null;
    private array $logs = [];
    private array $environmentOptions = [];
    private ?\Closure $connectionProbe = null;
    private ?\Closure $assetSynchronizer = null;

    public function __construct(string $projectRoot)
    {
        $resolvedRoot = realpath($projectRoot);
        $this->projectRoot = rtrim($resolvedRoot !== false ? $resolvedRoot : $projectRoot, '/');
        $this->yourShieldDir = $this->projectRoot . '/yourshield';
        $this->configPath = $this->yourShieldDir . '/config.php';
        $this->configLocalPath = $this->yourShieldDir . '/config.local.php';
        $this->bootstrapPath = $this->yourShieldDir . '/bootstrap.php';
        $this->backupDir = $this->selectPrivateBackupWorkspace();
    }

    public function setLogger(?callable $logger): void
    {
        $this->logger = $logger !== null ? \Closure::fromCallable($logger) : null;
    }

    public function getLogs(): array
    {
        return $this->logs;
    }

    public function resetLogs(): void
    {
        $this->logs = [];
    }

    public function install(array $options = []): int
    {
        return $this->withOperationLock(fn (): int => $this->installInternal($options));
    }

    private function installInternal(array $options): int
    {
        if (!$this->mutationOwnerIsValid()) {
            return 1;
        }
        if (!empty($options['probe_url']) && $this->normalizeProbeOrigin((string) $options['probe_url']) === null) {
            $this->log('Invalid probe_url.', 'error');
            return 1;
        }
        $runtimeEnv = $this->normalizeRuntimeOption($options['runtime_env'] ?? 'auto');
        if ($runtimeEnv === null) {
            $this->log('Unknown runtime_env. Allowed: auto|apache|litespeed|nginx|iis|caddy|php_builtin|unknown', 'error');
            return 1;
        }

        $this->environmentOptions = $options;
        try {
            $env = $this->discoverEnvironment($runtimeEnv);
        } catch (\Throwable $e) {
            $this->log($e->getMessage(), 'error');
            return 1;
        }
        if (Utils::pathIsInside($env['docroot'], $this->backupDir)) {
            $this->backupDir = rtrim(sys_get_temp_dir(), '/\\') . '/.yourshield-installer-' . bin2hex(random_bytes(12));
            if (Utils::pathIsInside($env['docroot'], $this->backupDir)) {
                $this->log('No private backup workspace outside document_root is available.', 'error');
                return 1;
            }
        }
        $requestedCms = strtolower(trim((string) ($options['cms'] ?? 'auto')));
        $cms = $this->resolveCms($requestedCms, $env);
        $useCmsPresets = $this->optionBool($options, 'use_cms_presets', true);

        $detectedEntrypoints = $this->entrypointsForCms($env['application_root'], $cms);
        if ($detectedEntrypoints === []) {
            $detectedEntrypoints = $env['entrypoints'];
        }

        $entrypoints = $this->entrypointsFromOptions($options, $detectedEntrypoints);
        $method = $this->integrationMethod($options, $env, $entrypoints);
        if ($method === 'entrypoint' && $entrypoints === []) {
            $this->log('No PHP entrypoints detected.', 'error');
            return 1;
        }

        if (!in_array($method, ['prepend', 'entrypoint', 'static', 'manual'], true)) {
            $this->log('Invalid integration_method.', 'error');
            return 1;
        }
        $local = $this->readLocalConfig();
        $previousLocal = $local;
        if (($previousLocal['enabled'] ?? false) && $method === 'manual'
            && ($previousLocal['integration']['method'] ?? 'entrypoint') !== 'manual'
        ) {
            $this->log('A manual hook cannot be distinguished from the existing active integration. Disable explicitly, connect the manual hook, then verify before activation.', 'error');
            return 1;
        }
        if (($previousLocal['enabled'] ?? false) && $method === 'entrypoint'
            && in_array($previousLocal['integration']['method'] ?? '', ['prepend', 'manual'], true)
        ) {
            $this->log('The existing global/manual hook can mask an unverified entrypoint replacement. Disable explicitly before changing to entrypoint mode, then verify the selected PHP entrypoints.', 'error');
            return 1;
        }
        $siteKey = isset($options['site_key']) ? trim((string) $options['site_key']) : null;
        $secret = isset($options['secret']) ? trim((string) $options['secret']) : null;
        $siteHost = isset($options['site_host']) ? Utils::canonicalHost((string) $options['site_host'])
            : Utils::resolveSiteHost($_SERVER, (string) ($local['site_host'] ?? ''));
        if (array_key_exists('site_host', $options) && $siteHost === '') {
            $this->log('Invalid site_host. Use a hostname without scheme or path.', 'error');
            return 1;
        }
        $cloudUrl = isset($options['cloud_url']) ? trim((string) $options['cloud_url']) : null;
        $assetsAutoEnabled = $this->optionBool(
            $options,
            'assets_auto_update_enabled',
            (bool) (($local['assets']['auto_update']['enabled'] ?? true))
        );
        $assetsAutoInterval = $this->optionInt(
            $options,
            'assets_auto_update_interval_sec',
            is_numeric($local['assets']['auto_update']['interval_sec'] ?? null)
                ? (int) $local['assets']['auto_update']['interval_sec']
                : 900
        );
        $assetsAutoInterval = max(60, $assetsAutoInterval);
        $moduleAutoEnabled = $this->optionBool(
            $options,
            'module_auto_update_enabled',
            (bool) (($local['module_update']['enabled'] ?? true))
        );
        $moduleAutoInterval = $this->optionInt(
            $options,
            'module_auto_update_interval_sec',
            is_numeric($local['module_update']['interval_sec'] ?? null)
                ? (int) $local['module_update']['interval_sec']
                : 21600
        );
        $moduleAutoInterval = max(300, $moduleAutoInterval);
        $botBlockMode = $this->normalizeBotBlockMode($options['bot_block_mode'] ?? ($local['bot_blocking']['mode'] ?? 'block'));
        if ($botBlockMode === null) {
            $this->log('Unknown bot_block_mode. Allowed: block|whitepage_dir', 'error');
            return 1;
        }
        $botWhitepageDirRaw = array_key_exists('bot_whitepage_dir', $options)
            ? trim((string) $options['bot_whitepage_dir'])
            : trim((string) ($local['bot_blocking']['whitepage_dir'] ?? ''));
        $botWhitepageDir = '';
        if ($botBlockMode === 'whitepage_dir') {
            $normalizedWhitepageDir = BotBlockPageResolver::normalizeDirectory($botWhitepageDirRaw);
            if ($normalizedWhitepageDir === null) {
                $this->log('bot_whitepage_dir is required for bot_block_mode=whitepage_dir and must not contain "..".', 'error');
                return 1;
            }
            $whitepageFiles = BotBlockPageResolver::collectFiles((string) ($env['docroot'] ?? ''), $normalizedWhitepageDir);
            if ($whitepageFiles === []) {
                $this->log('No HTML files found in bot_whitepage_dir: ' . $normalizedWhitepageDir, 'error');
                return 1;
            }
            $botWhitepageDir = $normalizedWhitepageDir;
        }
        $basePath = isset($options['base_path']) ? trim((string) $options['base_path']) : '';
        if ($basePath === '') {
            $localBasePath = is_string($local['base_path'] ?? null) ? trim((string) $local['base_path']) : '';
            if ($localBasePath !== '') {
                $normalizedLocalBasePath = $this->normalizeBasePath($localBasePath);
                $basePath = $normalizedLocalBasePath === '/assets/.cache/ys_demo'
                    ? $this->generateBasePath()
                    : $normalizedLocalBasePath;
            } else {
                $basePath = $this->generateBasePath();
            }
        }
        $basePath = $this->mountedBasePath($basePath, $env['mount_path']);
        if (!$this->basePathStaysInsideDocroot($env['docroot'], $basePath)) {
            $this->log('base_path must stay inside docroot and must not contain "." or "..".', 'error');
            return 1;
        }

        $assetBase = $this->managedAssetBase((string) $env['docroot'], $basePath);
        if ($assetBase === null) {
            $this->log('Refused asset path outside project docroot.', 'error');
            return 1;
        }
        $previousAssetBase = null;
        $previousPublicRoot = is_string($local['public_root'] ?? null) ? trim((string) $local['public_root']) : '';
        $previousBasePath = is_string($local['base_path'] ?? null) ? trim((string) $local['base_path']) : '';
        $hasPreviousInstall = trim((string) ($local['installed_at'] ?? '')) !== ''
            || (is_array($local['managed_entrypoints'] ?? null) && $local['managed_entrypoints'] !== [])
            || (is_array($local['managed_htaccess_files'] ?? null) && $local['managed_htaccess_files'] !== []);
        if ($hasPreviousInstall) {
            if ($previousPublicRoot === '' || $previousBasePath === '') {
                $this->log('Previous managed asset path is incomplete.', 'error');
                return 1;
            }
            $previousAssetBase = $this->managedAssetBase($previousPublicRoot, $previousBasePath);
            if ($previousAssetBase === null) {
                $this->log('Refused unsafe previous managed asset path.', 'error');
                return 1;
            }
        }

        $assetRoot = $assetBase . '/a';
        $options['integration_method'] = $method;
        $preflight = $this->preflightChecks($env, $method === 'entrypoint' ? $entrypoints : [], $assetRoot, $options);
        foreach ($preflight as $check) {
            if ($check['ok'] !== true) {
                $this->log('Preflight failed: ' . $check['label'] . ' (' . $check['detail'] . ')', 'error');
            }
        }
        if (array_filter($preflight, static fn (array $check): bool => $check['ok'] !== true) !== []) {
            return 1;
        }

        try {
            $runtimeConfig = $this->runtimeConfigForOptions($options);
            $runtimeDir = $runtimeConfig->getString('runtime_dir');
            $runtimeCacheDir = $runtimeConfig->getString('cache_dir');
        } catch (\Throwable $e) {
            $this->log('Runtime config changed after preflight: ' . $e->getMessage(), 'error');
            return 1;
        }
        $connection = $this->checkConnection($runtimeConfig, $options);
        if (!$connection['ok']) {
            $this->log($connection['detail'], 'error');
            return 1;
        }
        if (!$this->cleanupLegacyModuleCache($runtimeCacheDir)) {
            $this->log('Failed to remove legacy public runtime cache.', 'error');
            return 1;
        }

        $journal = [];
        $directories = [];
        if ($runtimeDir !== '') {
            $directories[$runtimeDir] = 0700;
        }
        $directories[$runtimeCacheDir] = 0700;
        $directories[$this->backupDir] = 0700;
        $directories[$assetRoot] = 0775;
        foreach ($directories as $directory => $mode) {
            if (!$this->ensureDirectory($directory, $mode, $journal)) {
                $this->log("Failed to create install directory: {$directory}", 'error');
                $this->rollbackInstall($journal);
                return 1;
            }
        }

        $managed = [];
        // Older flat installations acquire these stable entry files on the first reinstall
        // after an immutable upgrade. Never replace an existing stable file during update.
        foreach (['prepend.php', 'gateway.php', 'validator.php'] as $helper) {
            $destination = $this->yourShieldDir . '/' . $helper;
            if (is_link($destination) || (file_exists($destination) && !is_file($destination))) {
                $this->log('Unsafe stable integration entry file: ' . $helper, 'error');
                $this->rollbackInstall($journal);
                return 1;
            }
            if (!file_exists($destination)) {
                $source = dirname(__DIR__) . '/' . $helper;
                $content = is_file($source) && !is_link($source) ? file_get_contents($source) : false;
                if (!is_string($content) || !$this->writeIntegrationFile($destination, $content, $journal)) {
                    $this->log('Cannot provision stable integration entry file: ' . $helper, 'error');
                    $this->rollbackInstall($journal);
                    return 1;
                }
            }
        }
        foreach ($method === 'entrypoint' ? $entrypoints : [] as $entrypoint) {
            $result = $this->patchEntrypoint($entrypoint);
            if (!$result['ok']) {
                $this->log("Failed to patch entrypoint: {$entrypoint}", 'error');
                if (isset($result['error']) && is_string($result['error'])) {
                    $this->log($result['error'], 'error');
                }
                $this->rollbackInstall($journal);
                return 1;
            }
            if (($result['changed'] ?? false) === true) {
                $journal[] = ['type' => 'file', 'path' => $entrypoint, 'backup' => $result['backup'] ?? null];
            }
            $managed[] = $this->relativeToProject($entrypoint);
        }
        $managed = array_values(array_unique($managed));

        $integration = $this->configureIntegration($method, $env, $local, $journal);
        if ($integration === null) {
            $this->rollbackInstall($journal);
            return 1;
        }
        if ($method === 'static') {
            $entrypoints = [$env['application_root'] . '/ys-gateway.php'];
        }
        $routingSetup = $this->setupRouting($env, $basePath, $entrypoints);
        if ($routingSetup['ok'] !== true) {
            $this->rollbackInstall($journal);
            return 1;
        }
        foreach ((array) ($routingSetup['journal'] ?? []) as $entry) {
            if (is_array($entry)) {
                $journal[] = $entry;
            }
        }
        $local['enabled'] = false;
        $local['document_root'] = $env['docroot'];
        $local['mount_path'] = $env['mount_path'];
        $local['application_root'] = $env['application_root'];
        $local['integration'] = $integration;
        $local['installation'] = [
            'status' => 'needs_action',
            'method' => $method,
            'coverage' => $this->coverageDescription($method),
            'notes' => $integration['notes'],
            'checked_at' => gmdate('c'),
        ];
        $local['project_root'] = $this->projectRoot;
        $local['public_root'] = $env['docroot'];
        $local['base_path'] = $basePath;
        if (array_key_exists('runtime_dir', $options) || array_key_exists('cache_dir', $options)) {
            $local['runtime_dir'] = $runtimeDir;
            $local['cache_dir'] = $runtimeCacheDir;
            $local['runtime_storage_managed'] = false;
        }
        $local['cms_profile'] = $cms;
        $local['cms_detected'] = $env['cms'];
        if (array_key_exists('browser_proof_enabled', $options)) {
            $local['browser_proof']['enabled'] = $this->optionBool($options, 'browser_proof_enabled', true);
        }
        $local['managed_entrypoints'] = $managed;
        $local['managed_htaccess_files'] = $routingSetup['managed_htaccess_files'];
        $local['runtime_environment'] = [
            'kind' => (string) ($env['runtime']['kind'] ?? 'unknown'),
            'detected_by' => (string) ($env['runtime']['detected_by'] ?? 'auto'),
            'server_software' => (string) ($env['runtime']['server_software'] ?? ''),
            'htaccess_support' => (string) ($env['runtime']['htaccess_support'] ?? 'unknown'),
        ];
        $local['routing_setup'] = [
            'mode' => (string) ($routingSetup['mode'] ?? 'manual'),
            'rewrite_target' => (string) ($routingSetup['rewrite_target'] ?? ''),
            'manual_required' => (bool) ($routingSetup['manual_required'] ?? false),
            'manual_notes' => is_array($routingSetup['manual_notes'] ?? null) ? $routingSetup['manual_notes'] : [],
        ];
        $local['installed_at'] = gmdate('c');
        if ($useCmsPresets) {
            $local = $this->applyCmsPresets($local, $cms);
        }
        if ($siteKey !== null && $siteKey !== '') {
            $local['site_key'] = $siteKey;
        }
        if ($secret !== null && $secret !== '') {
            $local['secret'] = $secret;
        }
        if ($siteHost !== null) {
            $local['site_host'] = $siteHost;
        }
        if ($cloudUrl !== null && $cloudUrl !== '') {
            $normalizedCloudUrl = rtrim($cloudUrl, '/');
            $urlIssue = Utils::validateCloudBaseUrl($normalizedCloudUrl, $this->currentCloudUrlPolicy());
            if ($urlIssue !== null) {
                $this->log("Rejected cloud_url: {$urlIssue}", 'error');
                $this->rollbackInstall($journal);
                return 1;
            }
            $local['cloud_base_url'] = $normalizedCloudUrl;
        }
        $local['assets'] = is_array($local['assets'] ?? null) ? $local['assets'] : [];
        $local['assets']['auto_update'] = is_array($local['assets']['auto_update'] ?? null) ? $local['assets']['auto_update'] : [];
        $local['assets']['auto_update']['enabled'] = $assetsAutoEnabled;
        $local['assets']['auto_update']['interval_sec'] = $assetsAutoInterval;
        $local['module_update'] = is_array($local['module_update'] ?? null) ? $local['module_update'] : [];
        $local['module_update']['enabled'] = $moduleAutoEnabled;
        $local['module_update']['interval_sec'] = $moduleAutoInterval;
        $verificationOrigin = $this->normalizeProbeOrigin((string) ($options['probe_url'] ?? ''));
        if ($verificationOrigin !== null
            && Utils::canonicalHost((string) parse_url($verificationOrigin, PHP_URL_HOST)) === $siteHost
        ) {
            if (!$this->prepareNativeValidator($local, $verificationOrigin, $journal)) {
                $this->rollbackInstall($journal);
                return 1;
            }
        }
        $local['bot_blocking'] = [
            'mode' => $botBlockMode,
            'whitepage_dir' => $botWhitepageDir,
        ];

        $trustedProxyResult = $this->applyTrustedProxyOptions($local, $options);
        if ($trustedProxyResult['ok'] !== true) {
            $this->rollbackInstall($journal);
            return 1;
        }
        $local = $trustedProxyResult['local'];

        $cacheResult = $this->applyCacheOptions($local, $options);
        if ($cacheResult['ok'] !== true) {
            $this->rollbackInstall($journal);
            return 1;
        }
        $local = $cacheResult['local'];

        $configBackup = is_file($this->configLocalPath) ? $this->createPrivateBackup($this->configLocalPath) : null;
        if (is_file($this->configLocalPath) && $configBackup === null) {
            $this->log("Failed to back up local config: {$this->configLocalPath}", 'error');
            $this->rollbackInstall($journal);
            return 1;
        }
        $journal[] = ['type' => 'file', 'path' => $this->configLocalPath, 'backup' => $configBackup];
        if (!($previousLocal['enabled'] ?? false) && !$this->writeLocalConfig($local)) {
            $this->log("Failed to write local config: {$this->configLocalPath}", 'error');
            $this->rollbackInstall($journal);
            return 1;
        }

        // Assets are acquired before activation; failures restore the previous installation.
        $assetAgent = new Agent(new RuntimeConfig(array_replace_recursive(RuntimeConfig::fromFile($this->configPath)->all(), $local)));
        $assetAgent->setLogger(function (string $level, string $message): void { $this->log($message, $level); });
        $assetsCode = $this->assetSynchronizer !== null ? ($this->assetSynchronizer)() : $assetAgent->updateAssets();
        if ($assetsCode !== 0) {
            $this->log('Initial challenge assets could not be verified.', 'error');
            $this->rollbackInstall($journal);
            return 1;
        }
        $this->log('Installation staged. Protection activates after connection and hook verification.');
        $this->log('Coverage: ' . $local['installation']['coverage']);
        foreach ($integration['notes'] as $note) {
            $this->log($note, 'warning');
        }
        $probeUrl = trim((string) ($options['probe_url'] ?? ''));
        $status = $probeUrl !== '' ? $this->verifyAndActivate($probeUrl, ($previousLocal['enabled'] ?? false) ? $local : null) : 2;
        if ($status !== 0 && ($previousLocal['enabled'] ?? false)) {
            $this->rollbackInstall($journal);
            $this->log('Previous active installation restored; new integration needs verification.', 'warning');
            return 1;
        }

        foreach ((array) ($previousLocal['integration']['files'] ?? []) as $oldFile) {
            if (is_array($oldFile) && !in_array($oldFile, $integration['files'], true)
                && !$this->removeIntegrationFile($oldFile, $journal)
            ) {
                $this->rollbackInstall($journal);
                return 1;
            }
        }
        if (!$this->retirePreviousInstall(
            $previousLocal,
            $managed,
            (array) ($routingSetup['managed_htaccess_files'] ?? []),
            $previousAssetBase,
            $assetBase,
            $journal
        )) {
            $this->rollbackInstall($journal);
            return 1;
        }

        $cleanupOk = $this->cleanupLegacyPublicBackups($env['docroot']);
        $cleanupOk = $this->cleanupBackupStorage() && $cleanupOk;
        if (!$cleanupOk) {
            $this->log('Install completed, but legacy or private transaction backups could not be removed.', 'error');
            return 1;
        }

        return $status;
    }

    public function cleanupCache(): int
    {
        if (!$this->mutationOwnerIsValid()) {
            return 1;
        }
        $config = RuntimeConfig::fromFile($this->configPath);
        $cache = new FileCache($config->getString('cache_dir'));
        $this->log('Removed expired file-cache entries: ' . $cache->collectExpired());
        return 0;
    }

    public function scan(array $options = []): array
    {
        $this->environmentOptions = $options;
        return $this->discoverEnvironment();
    }

    public function getState(): array
    {
        $state = (array) ($this->readLocalConfig()['installation'] ?? []);
        unset($state['probe_hash'], $state['probe_expires_at']);
        return $state;
    }

    public function disable(): int
    {
        return $this->withOperationLock(fn (): int => $this->disableInternal());
    }

    private function disableInternal(): int
    {
        if (!$this->mutationOwnerIsValid()) {
            return 1;
        }
        $local = $this->readLocalConfig();
        $local['enabled'] = false;
        $local['installation']['status'] = 'disabled';
        unset($local['installation']['probe_hash'], $local['installation']['probe_expires_at']);
        return $this->writeLocalConfig($local) ? 0 : 1;
    }

    public function preflight(array $options = []): array
    {
        $runtimeEnv = $this->normalizeRuntimeOption($options['runtime_env'] ?? 'auto');
        if ($runtimeEnv === null) {
            return [[
                'key' => 'runtime_environment',
                'label' => 'runtime environment valid',
                'ok' => false,
                'detail' => 'auto|apache|litespeed|nginx|iis|caddy|php_builtin|unknown',
            ]];
        }

        $this->environmentOptions = $options;
        try {
            $env = $this->discoverEnvironment($runtimeEnv);
        } catch (\Throwable $e) {
            return [['key' => 'document_root', 'label' => 'Document root and mount', 'ok' => false, 'detail' => $e->getMessage()]];
        }
        $cms = $this->resolveCms(strtolower(trim((string) ($options['cms'] ?? 'auto'))), $env);
        $detected = $this->entrypointsForCms($env['application_root'], $cms);
        if ($detected === []) {
            $detected = $env['entrypoints'];
        }
        $entrypoints = $this->entrypointsFromOptions($options, $detected);
        $method = $this->integrationMethod($options, $env, $entrypoints);
        $options['integration_method'] = $method;
        if ($method === 'entrypoint' && $entrypoints === []) {
            return [[
                'key' => 'entrypoint_writable',
                'label' => 'entrypoint writable',
                'ok' => false,
                'detail' => 'No PHP entrypoints detected',
            ]];
        }

        $basePath = trim((string) ($options['base_path'] ?? ''));
        $basePath = $this->mountedBasePath($basePath === '' ? $this->basePathFromConfigFallback() : $basePath, $env['mount_path']);
        if (!$this->basePathStaysInsideDocroot($env['docroot'], $basePath)) {
            return [[
                'key' => 'asset_root_writable',
                'label' => 'asset root writable',
                'ok' => false,
                'detail' => 'base_path escapes docroot',
            ]];
        }

        $assetRoot = $env['docroot'] . '/' . trim($basePath, '/') . '/a';
        return $this->preflightChecks($env, $method === 'entrypoint' ? $entrypoints : [], $assetRoot, $options);
    }

    public function test(array $options = []): int
    {
        if (in_array($this->getState()['status'] ?? '', ['needs_action', 'disabled', 'active'], true) && trim((string) ($options['probe_url'] ?? '')) !== '') {
            return $this->withOperationLock(fn (): int => $this->verifyAndActivate((string) $options['probe_url']));
        }
        $checks = [];
        $checks[] = ['Bootstrap file', is_file($this->bootstrapPath), $this->bootstrapPath];
        $checks[] = ['Config file', is_file($this->configPath), $this->configPath];
        $checks[] = ['PHP cURL extension', extension_loaded('curl'), 'ext-curl'];

        if (!is_file($this->configPath)) {
            $this->printChecks($checks);
            return 1;
        }

        $runtime = RuntimeConfig::fromFile($this->configPath);
        $siteKey = $runtime->getString('site_key');
        $secret = $runtime->getString('secret');
        $basePath = $runtime->getString('base_path');
        $basePathOverride = isset($options['base_path']) ? trim((string) $options['base_path']) : '';
        $hasBasePathOverride = $basePathOverride !== '';
        if ($hasBasePathOverride) {
            $basePath = $this->normalizeBasePath($basePathOverride);
        }
        $cacheDir = $runtime->getString('cache_dir');
        $routeBundle = $runtime->getArray('route_bundle');
        $routeBundleForProbe = $routeBundle;
        if ($hasBasePathOverride) {
            $routeBundleForProbe = is_array($routeBundleForProbe) ? $routeBundleForProbe : [];
            $routeBundleCurrent = is_array($routeBundleForProbe['current'] ?? null) ? $routeBundleForProbe['current'] : [];
            $challengePath = is_string($routeBundleCurrent['challenge_path'] ?? null) ? (string) $routeBundleCurrent['challenge_path'] : '';
            if ($challengePath === '' || str_contains($challengePath, '/assets/.cache/ys_demo/')) {
                $routeBundleCurrent['challenge_path'] = rtrim($basePath, '/') . '/c/bootstrap';
            }
            $routeBundleForProbe['current'] = $routeBundleCurrent;
        }
        $publicRoot = $runtime->getString('public_root');
        $cmsProfile = $runtime->getString('cms_profile');

        $checks[] = ['site_key configured', $siteKey !== '' && $siteKey !== 'replace-with-site-key', 'site_key'];
        $checks[] = ['secret configured', $secret !== '' && $secret !== 'replace-with-secret', 'secret'];
        $checks[] = ['base_path valid', str_starts_with($basePath, '/'), $basePath];
        $checks[] = ['cache dir writable', is_dir($cacheDir) && is_writable($cacheDir), $cacheDir];
        $checks[] = [
            'route_bundle current complete',
            is_array($routeBundle['current'] ?? null)
                && is_string($routeBundle['current']['challenge_path'] ?? null)
                && is_string($routeBundle['current']['solve_path'] ?? null)
                && is_string($routeBundle['current']['session_ingest_path'] ?? null)
                && is_string($routeBundle['current']['metrics_ingest_path'] ?? null),
            'route_bundle.current',
        ];

        if ($publicRoot === '') {
            $env = $this->discoverEnvironment();
            $publicRoot = $env['docroot'];
        }

        $checks[] = ['public root exists', is_dir($publicRoot), $publicRoot];
        $assetRoot = rtrim($publicRoot, '/') . '/' . trim($basePath, '/') . '/a';
        $checks[] = ['asset root exists', is_dir($assetRoot), $assetRoot];
        if ($cmsProfile !== '') {
            $checks[] = ['cms profile set', in_array($cmsProfile, ['wordpress', 'laravel', 'symfony', 'generic'], true), $cmsProfile];
        }

        $probeUrl = trim((string) ($options['probe_url'] ?? ''));
        if ($probeUrl !== '') {
            $checks = array_merge(
                $checks,
                $this->probeLiveIntegration($runtime, $probeUrl, $basePath, $routeBundleForProbe, $assetRoot)
            );
        }

        $this->printChecks($checks);
        foreach ($checks as $check) {
            if ($check[1] !== true) {
                return 1;
            }
        }

        return 0;
    }

    public function updateAssets(): int
    {
        if (!$this->mutationOwnerIsValid()) {
            return 1;
        }
        if (!is_file($this->configPath)) {
            $this->log("Missing config file: {$this->configPath}", 'error');
            return 1;
        }

        $runtime = RuntimeConfig::fromFile($this->configPath);
        $agent = new Agent($runtime);
        $agent->setLogger(function (string $level, string $message): void {
            $this->log($message, $level);
        });
        return $agent->updateAssets();
    }

    public function updateModule(): int
    {
        if (!$this->mutationOwnerIsValid()) {
            return 1;
        }
        if (!is_file($this->configPath)) {
            $this->log("Missing config file: {$this->configPath}", 'error');
            return 1;
        }

        $runtime = RuntimeConfig::fromFile($this->configPath);
        $agent = new Agent($runtime);
        $agent->setLogger(function (string $level, string $message): void {
            $this->log($message, $level);
        });
        return $agent->updateModule();
    }

    public function uninstall(): int
    {
        return $this->withOperationLock(fn (): int => $this->uninstallInternal());
    }

    public function rollback(): int
    {
        return $this->withOperationLock(function (): int {
            if (!$this->mutationOwnerIsValid()) {
                return 1;
            }
            $runtime = RuntimeConfig::fromFile($this->configPath);
            $updater = new ModuleUpdater($runtime, new CloudClient($runtime, new HttpClient(), new HmacSigner()));
            $updater->setLogger(function (string $level, string $message): void { $this->log($message, $level); });
            return $updater->rollback();
        });
    }

    private function uninstallInternal(): int
    {
        if (!$this->mutationOwnerIsValid()) {
            return 1;
        }
        $local = $this->readLocalConfig();
        $journal = [];
        $publicRoot = is_string($local['public_root'] ?? null) ? trim((string) $local['public_root']) : '';
        $basePath = is_string($local['base_path'] ?? null) ? trim((string) $local['base_path']) : '';
        $assetBase = null;
        if ($publicRoot !== '' || $basePath !== '') {
            if ($publicRoot === '' || $basePath === '') {
                $this->log('Refused incomplete managed asset path during uninstall.', 'error');
                return 1;
            }
            $assetBase = $this->managedAssetBase($publicRoot, $basePath);
            if ($assetBase === null) {
                $this->log('Refused unsafe managed asset path during uninstall.', 'error');
                return 1;
            }
        }
        $runtimeDir = '';
        $runtimeStorageManaged = false;
        $runtimeConfigOk = true;
        try {
            $runtimeConfig = RuntimeConfig::fromFile($this->configPath);
            $cacheDir = $runtimeConfig->getString('cache_dir');
            $runtimeDir = $runtimeConfig->getString('runtime_dir');
            $runtimeStorageManaged = $runtimeConfig->getBool('runtime_storage_managed');
        } catch (\Throwable $e) {
            $cacheDir = '';
            $runtimeConfigOk = false;
            $this->log('Runtime storage could not be validated during uninstall: ' . $e->getMessage(), 'error');
        }
        $env = $this->discoverEnvironment();
        $configBackup = is_file($this->configLocalPath) ? $this->createPrivateBackup($this->configLocalPath) : null;
        if (is_file($this->configLocalPath) && $configBackup === null) {
            return 1;
        }
        $journal[] = ['type' => 'file', 'path' => $this->configLocalPath, 'backup' => $configBackup];
        if ($this->disableInternal() !== 0) {
            $this->rollbackInstall($journal);
            return 1;
        }
        foreach ((array) ($local['integration']['files'] ?? []) as $file) {
            if (!is_array($file) || !$this->removeIntegrationFile($file, $journal)) {
                $this->rollbackInstall($journal);
                return 1;
            }
        }
        $managed = is_array($local['managed_entrypoints'] ?? null) ? $local['managed_entrypoints'] : [];
        if ($managed === []) {
            $managed = array_map([$this, 'relativeToProject'], $env['entrypoints']);
        }

        foreach ($managed as $entryRel) {
            if (!is_string($entryRel) || $entryRel === '') {
                continue;
            }
            $entry = $this->resolveProjectFile($entryRel, 'php');
            if ($entry === null) {
                continue;
            }
            $result = $this->unpatchEntrypoint($entry);
            if (!$result['ok']) {
                $this->log("Failed to unpatch entrypoint: {$entryRel}", 'error');
                if (isset($result['error']) && is_string($result['error'])) {
                    $this->log($result['error'], 'error');
                }
                $this->rollbackInstall($journal);
                return 1;
            }
            if (($result['changed'] ?? false) === true) {
                $journal[] = ['type' => 'file', 'path' => $entry, 'backup' => $result['backup'] ?? null];
            }
        }

        $managedHtaccessFiles = is_array($local['managed_htaccess_files'] ?? null) ? $local['managed_htaccess_files'] : [];
        if ($managedHtaccessFiles === []) {
            if ($publicRoot !== '' && $basePath !== '') {
                $fallbackHtaccess = rtrim($publicRoot, '/') . '/' . trim($basePath, '/') . '/.htaccess';
                if (
                    $this->basePathStaysInsideDocroot($publicRoot, $basePath)
                    && $this->resolveProjectFile($fallbackHtaccess) !== null
                ) {
                    $managedHtaccessFiles[] = $this->relativeToProject($fallbackHtaccess);
                }
            }
        }

        foreach ($managedHtaccessFiles as $htaccessRel) {
            if (!is_string($htaccessRel) || $htaccessRel === '') {
                continue;
            }
            $htaccessPath = $this->resolveProjectFile($htaccessRel);
            if ($htaccessPath === null) {
                continue;
            }
            $result = $this->unpatchHtaccess($htaccessPath);
            if (!$result['ok']) {
                $this->log("Failed to unpatch .htaccess: {$htaccessRel}", 'error');
                if (isset($result['error']) && is_string($result['error'])) {
                    $this->log($result['error'], 'error');
                }
                $this->rollbackInstall($journal);
                return 1;
            }
            if (($result['changed'] ?? false) === true) {
                $journal[] = ['type' => 'file', 'path' => $htaccessPath, 'backup' => $result['backup'] ?? null];
            }
        }

        $local['enabled'] = false;
        $local['site_key'] = '';
        $local['secret'] = '';
        $local['managed_entrypoints'] = [];
        $local['managed_htaccess_files'] = [];
        $local['cache'] = is_array($local['cache'] ?? null) ? $local['cache'] : [];
        $local['cache']['redis'] = is_array($local['cache']['redis'] ?? null) ? $local['cache']['redis'] : [];
        $local['cache']['redis']['password'] = '';
        $local['web_installer'] = is_array($local['web_installer'] ?? null) ? $local['web_installer'] : [];
        $local['web_installer']['enabled'] = false;
        $local['web_installer']['token'] = '';
        $local['uninstalled_at'] = gmdate('c');
        $local['installation'] = ['status' => 'uninstalled'];
        $local['integration']['files'] = [];
        unset($local['module_update']['validator_token'], $local['module_update']['validator_url']);
        if (!$this->writeLocalConfig($local)) {
            $this->log('Failed to write local config during uninstall.', 'error');
            $this->rollbackInstall($journal);
            return 1;
        }

        $cleanupOk = $runtimeConfigOk;
        if ($assetBase !== null) {
            $cleanupOk = $this->removeManagedTree($assetBase . '/a', $assetBase) && $cleanupOk;
            $this->removeEmptyParents($assetBase, $publicRoot);
        }
        $cleanupOk = $this->cleanupManagedRuntimeStorage(
            $runtimeDir,
            $cacheDir,
            $runtimeStorageManaged
        ) && $cleanupOk;
        $cleanupOk = $this->cleanupLegacyModuleCache($cacheDir) && $cleanupOk;
        $cleanupOk = $this->cleanupLegacyPublicBackups((string) ($env['docroot'] ?? '')) && $cleanupOk;
        $cleanupOk = $this->cleanupBackupStorage() && $cleanupOk;
        if (!$cleanupOk) {
            $this->log('Uninstall disabled the module but could not remove every managed runtime file.', 'error');
            return 1;
        }

        $this->log('Uninstall completed. Bootstrap, secrets and managed runtime files were removed.');
        return 0;
    }

    private function discoverEnvironment(string $runtimeOverride = 'auto'): array
    {
        $cms = $this->detectCms();
        $local = $this->readLocalConfig();
        $defaultRoot = $cms !== 'wordpress' && is_file($this->projectRoot . '/public/index.php')
            ? $this->projectRoot . '/public' : $this->projectRoot;
        $options = $this->environmentOptions;
        $requestedRoot = (string) ($options['document_root'] ?? $local['document_root'] ?? $defaultRoot);
        $docroot = realpath($requestedRoot);
        if ($docroot === false || !is_dir($docroot) || $this->pathHasSymlink($requestedRoot)
            || (!Utils::pathIsInside($this->projectRoot, $docroot) && !Utils::pathIsInside($docroot, $this->projectRoot))
        ) {
            throw new \InvalidArgumentException('document_root must be a regular directory containing, or contained by, this project.');
        }
        $docroot = rtrim(str_replace('\\', '/', $docroot), '/');
        $mount = trim((string) ($options['mount_path'] ?? $local['mount_path'] ?? ''));
        $mount = $mount === '/' ? '' : rtrim($mount, '/');
        if ($mount !== '' && (!preg_match('~^/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+$~D', $mount))) {
            throw new \InvalidArgumentException('mount_path must be empty or a URL path such as /shop.');
        }
        $appRoot = $docroot . $mount;
        if (!is_dir($appRoot) || $this->pathHasSymlink($appRoot) || !Utils::pathIsInside($this->projectRoot, $appRoot)) {
            throw new \InvalidArgumentException('The document_root + mount_path directory must exist inside the project.');
        }
        $entrypoints = $this->entrypointsForCms($appRoot, $cms);
        $runtime = $this->detectRuntimeEnvironment($runtimeOverride, $docroot);
        $rewriteTarget = $this->resolveRewriteTarget($entrypoints, $docroot);
        $runtime['rewrite_target_hint'] = $rewriteTarget ?? $mount . '/ys-gateway.php';
        $runtime['manual_routing_hints'] = $this->manualRoutingHints(
            $runtime['kind'], $this->mountedBasePath($this->basePathFromConfigFallback(), $mount),
            $runtime['rewrite_target_hint']
        );
        $env = [
            'project_root' => $this->projectRoot,
            'docroot' => $docroot,
            'document_root' => $docroot,
            'application_root' => $appRoot,
            'mount_path' => $mount,
            'entrypoints' => $entrypoints,
            'cms' => $cms,
            'runtime' => $runtime,
            'capabilities' => [
                'php_cli' => Utils::resolvePhpCli() !== null,
                'prepend_support' => in_array(PHP_SAPI, ['cgi-fcgi', 'fpm-fcgi', 'apache2handler'], true),
                'open_basedir' => (string) ini_get('open_basedir'),
                'user_ini_cache_ttl' => (int) ini_get('user_ini.cache_ttl'),
            ],
        ];
        $env['integration_method'] = $this->integrationMethod($options, $env, $entrypoints);
        return $env;
    }

    private function entrypointsFromOptions(array $options, array $detected): array
    {
        $raw = isset($options['entrypoints']) ? trim((string) $options['entrypoints']) : '';
        $result = [];
        $parts = $raw === '' ? $detected : explode(',', $raw);
        foreach ($parts as $part) {
            $part = trim((string) $part);
            if ($part === '') {
                continue;
            }
            $resolved = $this->resolveProjectFile($part, 'php');
            if ($resolved === null) {
                if ($raw !== '') {
                    $this->log("Rejected entrypoint: {$part}", 'error');
                    return [];
                }
                continue;
            }
            $result[] = $resolved;
        }
        return array_values(array_unique($result));
    }

    private function preflightChecks(array $env, array $entrypoints, string $assetRoot, array $options = []): array
    {
        $checks = [
            [
                'key' => 'php_version',
                'label' => 'PHP version',
                'ok' => PHP_VERSION_ID >= 80000,
                'detail' => PHP_VERSION . ' (required >= 8.0)',
            ],
            [
                'key' => 'curl_extension',
                'label' => 'cURL extension',
                'ok' => extension_loaded('curl'),
                'detail' => 'ext-curl',
            ],
            [
                'key' => 'config_readable',
                'label' => 'config readable',
                'ok' => is_file($this->configPath) && is_readable($this->configPath),
                'detail' => $this->configPath,
            ],
            [
                'key' => 'bootstrap_readable',
                'label' => 'bootstrap readable',
                'ok' => is_file($this->bootstrapPath) && is_readable($this->bootstrapPath),
                'detail' => $this->bootstrapPath,
            ],
            [
                'key' => 'config_storage_writable',
                'label' => 'config storage writable',
                'ok' => is_dir($this->yourShieldDir) && is_writable($this->yourShieldDir),
                'detail' => $this->yourShieldDir,
            ],
            [
                'key' => 'backup_storage_writable',
                'label' => 'backup storage writable',
                'ok' => $this->pathCanBeCreated($this->backupDir)
                    && $this->pathCanBeCreated($this->yourShieldDir . '/.installer-backups'),
                'detail' => $this->backupDir
                    . ' (legacy cleanup: ' . $this->yourShieldDir . '/.installer-backups)',
            ],
            [
                'key' => 'asset_root_writable',
                'label' => 'asset root writable',
                'ok' => $this->pathCanBeCreated($assetRoot),
                'detail' => $assetRoot,
            ],
        ];

        $method = (string) ($options['integration_method'] ?? 'entrypoint');
        if ($method === 'entrypoint') {
            $checks[] = [
                'key' => 'php_cli', 'label' => 'PHP syntax validation',
                'ok' => Utils::resolvePhpCli() !== null,
                'detail' => 'Entrypoint changes require PHP CLI; choose prepend or manual integration when exec is disabled.',
            ];
        }
        if ($method === 'static') {
            $checks[] = [
                'key' => 'static_index', 'label' => 'Static HTML entry',
                'ok' => is_file($env['application_root'] . '/index.html') || is_file($env['application_root'] . '/index.htm'),
                'detail' => $env['application_root'] . '/index.html',
            ];
        }

        try {
            $runtimeConfig = $this->runtimeConfigForOptions($options);
            $runtimeDir = $runtimeConfig->getString('runtime_dir');
            $cacheDir = $runtimeConfig->getString('cache_dir');
            $docroot = (string) ($env['docroot'] ?? '');
            $checks[] = [
                'key' => 'runtime_storage_writable',
                'label' => 'runtime storage writable',
                'ok' => $runtimeDir !== ''
                    && !$this->pathIsInside($docroot, $runtimeDir)
                    && !$this->pathIsInside($runtimeDir, $docroot)
                    && $this->pathCanBeCreated($runtimeDir),
                'detail' => $runtimeDir,
            ];
            $checks[] = [
                'key' => 'cache_storage_writable',
                'label' => 'cache storage writable',
                'ok' => $cacheDir !== ''
                    && !$this->pathIsInside($docroot, $cacheDir)
                    && !$this->pathIsInside($cacheDir, $docroot)
                    && $this->pathCanBeCreated($cacheDir),
                'detail' => $cacheDir,
            ];
            $legacyCacheDir = $this->yourShieldDir . '/cache';
            $checks[] = [
                'key' => 'legacy_cache_cleanup_safe',
                'label' => 'legacy cache cleanup safe',
                'ok' => $this->samePath($cacheDir, $legacyCacheDir)
                    || $this->pathCanBeCreated($legacyCacheDir),
                'detail' => $legacyCacheDir,
            ];
        } catch (\Throwable $e) {
            $checks[] = [
                'key' => 'runtime_config_loadable',
                'label' => 'runtime config loadable',
                'ok' => false,
                'detail' => $e->getMessage(),
            ];
        }

        foreach ($entrypoints as $entrypoint) {
            $checks[] = [
                'key' => 'entrypoint_writable',
                'label' => 'entrypoint writable',
                'ok' => is_file($entrypoint) && is_readable($entrypoint) && is_writable($entrypoint),
                'detail' => $entrypoint,
            ];
        }

        $runtime = is_array($env['runtime'] ?? null) ? $env['runtime'] : [];
        $htaccessSupport = (string) ($runtime['htaccess_support'] ?? 'unknown');
        $docroot = rtrim((string) ($env['docroot'] ?? ''), '/');
        $rewriteTarget = $this->resolveRewriteTarget($entrypoints, $docroot);
        if ($htaccessSupport === 'supported' && $method === 'entrypoint') {
            $checks[] = [
                'key' => 'routing_target_available',
                'label' => 'routing target available',
                'ok' => $rewriteTarget !== null,
                'detail' => $rewriteTarget ?? 'no entrypoint inside docroot',
            ];
        }

        return $checks;
    }

    private function pathCanBeCreated(string $path): bool
    {
        if ($path === '' || $this->isFilesystemRoot($path) || $this->pathHasSymlink($path)) {
            return false;
        }
        if (is_dir($path)) {
            return is_writable($path);
        }
        if (file_exists($path) || is_link($path)) {
            return false;
        }

        $parent = dirname($path);
        while (!is_dir($parent)) {
            $next = dirname($parent);
            if ($next === $parent || file_exists($parent) || is_link($parent)) {
                return false;
            }
            $parent = $next;
        }
        return !is_link($parent) && is_writable($parent);
    }

    private function ensureDirectory(string $path, int $mode, array &$journal): bool
    {
        if ($path === '' || $this->isFilesystemRoot($path) || $this->pathHasSymlink($path)) {
            return false;
        }
        if (is_dir($path)) {
            return is_writable($path) && $this->enforcePosixMode($path, $mode);
        }

        $missing = [];
        $cursor = $path;
        while (!is_dir($cursor)) {
            if (file_exists($cursor) || is_link($cursor)) {
                return false;
            }
            array_unshift($missing, $cursor);
            $parent = dirname($cursor);
            if ($parent === $cursor) {
                return false;
            }
            $cursor = $parent;
        }

        if (!mkdir($path, $mode, true) && !is_dir($path)) {
            return false;
        }
        foreach ($missing as $directory) {
            $journal[] = ['type' => 'directory', 'path' => $directory];
        }
        return $this->enforcePosixMode($path, $mode);
    }

    private function rollbackInstall(array $journal): void
    {
        foreach (array_reverse($journal) as $entry) {
            $type = (string) ($entry['type'] ?? '');
            $path = (string) ($entry['path'] ?? '');
            if ($path === '') {
                continue;
            }

            if ($type === 'tree') {
                $backup = is_string($entry['backup'] ?? null) ? (string) $entry['backup'] : '';
                if ($backup !== '' && file_exists($backup) && !file_exists($path) && !@rename($backup, $path)) {
                    $this->log("Rollback failed for managed tree: {$path}; backup retained at {$backup}", 'error');
                }
                continue;
            }
            if ($type === 'directory') {
                @rmdir($path);
                continue;
            }
            if ($type !== 'file') {
                continue;
            }

            $backup = is_string($entry['backup'] ?? null) ? (string) $entry['backup'] : '';
            if ($backup !== '' && is_file($backup)) {
                if (!$this->restorePrivateBackup($backup, $path)) {
                    $this->log("Rollback failed for file: {$path}; backup retained at {$backup}", 'error');
                }
            } else {
                @unlink($path);
            }
            clearstatcache(true, $path);
            if (function_exists('opcache_invalidate')) {
                @opcache_invalidate($path, true);
            }
        }
    }

    private function retirePreviousInstall(
        array $local,
        array $currentEntrypoints,
        array $currentHtaccessFiles,
        ?string $previousAssetBase,
        string $currentAssetBase,
        array &$journal
    ): bool {
        $currentEntrypoints = array_values(array_filter(array_map(
            fn (string $path): ?string => $this->resolveProjectFile($path, 'php'),
            array_values(array_filter($currentEntrypoints, 'is_string'))
        )));
        foreach ((array) ($local['managed_entrypoints'] ?? []) as $entryRel) {
            if (!is_string($entryRel) || $entryRel === '') {
                continue;
            }
            $entry = $this->resolveProjectFile($entryRel, 'php');
            if ($entry === null || $this->pathListContains($currentEntrypoints, $entry)) {
                continue;
            }
            $result = $this->unpatchEntrypoint($entry);
            if (($result['ok'] ?? false) !== true) {
                $this->log("Failed to retire previous entrypoint: {$entryRel}", 'error');
                return false;
            }
            if (($result['changed'] ?? false) === true) {
                $journal[] = ['type' => 'file', 'path' => $entry, 'backup' => $result['backup'] ?? null];
            }
        }

        $previousHtaccessFiles = is_array($local['managed_htaccess_files'] ?? null)
            ? $local['managed_htaccess_files']
            : [];
        if ($previousHtaccessFiles === [] && $previousAssetBase !== null) {
            $previousHtaccessFiles[] = $this->relativeToProject($previousAssetBase . '/.htaccess');
        }
        $currentHtaccessFiles = array_values(array_filter(array_map(
            fn (string $path): ?string => $this->resolveProjectFile($path),
            array_values(array_filter($currentHtaccessFiles, 'is_string'))
        )));
        foreach ($previousHtaccessFiles as $htaccessRel) {
            if (!is_string($htaccessRel) || $htaccessRel === '') {
                continue;
            }
            $htaccess = $this->resolveProjectFile($htaccessRel);
            if ($htaccess === null || $this->pathListContains($currentHtaccessFiles, $htaccess)) {
                continue;
            }
            $result = $this->unpatchHtaccess($htaccess);
            if (($result['ok'] ?? false) !== true) {
                $this->log("Failed to retire previous .htaccess: {$htaccessRel}", 'error');
                return false;
            }
            if (($result['changed'] ?? false) === true) {
                $journal[] = ['type' => 'file', 'path' => $htaccess, 'backup' => $result['backup'] ?? null];
            }
        }

        return $previousAssetBase === null
            || $this->samePath($previousAssetBase, $currentAssetBase)
            || $this->stageManagedTreeRemoval($previousAssetBase . '/a', $previousAssetBase, $journal);
    }

    private function pathListContains(array $paths, string $candidate): bool
    {
        foreach ($paths as $path) {
            if (is_string($path) && $this->samePath($path, $candidate)) {
                return true;
            }
        }
        return false;
    }

    private function stageManagedTreeRemoval(string $path, string $allowedRoot, array &$journal): bool
    {
        if (!file_exists($path) && !is_link($path)) {
            return true;
        }
        $root = realpath($allowedRoot);
        $resolved = realpath($path);
        if (
            $root === false
            || $resolved === false
            || !is_dir($resolved)
            || is_link($path)
            || !Utils::pathIsInside($root, $resolved)
        ) {
            $this->log("Refused to retire unsafe managed tree: {$path}", 'error');
            return false;
        }
        if (!is_dir($this->backupDir) && !mkdir($this->backupDir, 0700, true) && !is_dir($this->backupDir)) {
            return false;
        }
        $backup = $this->backupDir . '/tree-' . bin2hex(random_bytes(6));
        if (!@rename($path, $backup)) {
            return false;
        }
        $journal[] = ['type' => 'tree', 'path' => $path, 'backup' => $backup];
        return true;
    }

    private function patchEntrypoint(string $path): array
    {
        $source = file_get_contents($path);
        if (!is_string($source)) {
            return ['ok' => false, 'error' => 'Cannot read file'];
        }

        if (str_contains($source, self::MARKER_START)) {
            return ['ok' => true, 'changed' => false];
        }

        $bootstrapLiteral = addslashes($this->bootstrapPath);
        $snippet = self::MARKER_START . "\n"
            . "require_once '" . $bootstrapLiteral . "';\n"
            . self::MARKER_END . "\n";

        $patched = $this->injectAfterOpenTag($source, $snippet);
        if ($patched === null) {
            return ['ok' => false, 'error' => 'Unable to find PHP opening tag'];
        }

        $backup = $this->createPrivateBackup($path);
        if ($backup === null) {
            return ['ok' => false, 'error' => 'Failed to create backup'];
        }

        if (file_put_contents($path, $patched) === false) {
            if (!$this->restorePrivateBackup($backup, $path)) {
                return ['ok' => false, 'error' => 'Failed to write patched file and rollback backup was retained'];
            }
            return ['ok' => false, 'error' => 'Failed to write patched file'];
        }

        if (!$this->lintPhpFile($path)) {
            if (!$this->restorePrivateBackup($backup, $path)) {
                return ['ok' => false, 'error' => 'Lint failed after patch and rollback backup was retained'];
            }
            return ['ok' => false, 'error' => 'Lint failed after patch, rollback applied'];
        }

        return ['ok' => true, 'changed' => true, 'backup' => $backup];
    }

    private function unpatchEntrypoint(string $path): array
    {
        $source = file_get_contents($path);
        if (!is_string($source)) {
            return ['ok' => false, 'error' => 'Cannot read file'];
        }

        if (!str_contains($source, self::MARKER_START)) {
            return ['ok' => true, 'changed' => false];
        }

        $pattern = '/' . preg_quote(self::MARKER_START, '/') . '.*?' . preg_quote(self::MARKER_END, '/') . '\s*/s';
        $patched = preg_replace($pattern, '', $source);
        if (!is_string($patched)) {
            return ['ok' => false, 'error' => 'Failed to remove marker block'];
        }

        $backup = $this->createPrivateBackup($path);
        if ($backup === null) {
            return ['ok' => false, 'error' => 'Failed to create backup'];
        }

        if (file_put_contents($path, $patched) === false) {
            if (!$this->restorePrivateBackup($backup, $path)) {
                return ['ok' => false, 'error' => 'Failed to write unpatched file and rollback backup was retained'];
            }
            return ['ok' => false, 'error' => 'Failed to write unpatched file'];
        }

        if (!$this->lintPhpFile($path)) {
            if (!$this->restorePrivateBackup($backup, $path)) {
                return ['ok' => false, 'error' => 'Lint failed after unpatch and rollback backup was retained'];
            }
            return ['ok' => false, 'error' => 'Lint failed after unpatch, rollback applied'];
        }

        return ['ok' => true, 'changed' => true, 'backup' => $backup];
    }

    private function setupRouting(array $env, string $basePath, array $entrypoints): array
    {
        $runtime = is_array($env['runtime'] ?? null) ? $env['runtime'] : [];
        $runtimeKind = (string) ($runtime['kind'] ?? 'unknown');
        $detectedBy = (string) ($runtime['detected_by'] ?? 'auto');
        $serverSoftware = trim((string) ($runtime['server_software'] ?? ''));
        $htaccessSupport = (string) ($runtime['htaccess_support'] ?? 'unknown');
        $docroot = rtrim((string) ($env['docroot'] ?? ''), '/');
        $rewriteTarget = $this->resolveRewriteTarget($entrypoints, $docroot);

        $this->log("Runtime detection: {$runtimeKind} (source={$detectedBy}, htaccess={$htaccessSupport})");
        if ($serverSoftware !== '') {
            $this->log("Server software: {$serverSoftware}");
        }

        $managedHtaccessFiles = [];
        $journal = [];
        $manualRequired = false;
        $manualNotes = [];
        $mode = 'manual';

        if ($htaccessSupport === 'supported') {
            if ($rewriteTarget === null) {
                $this->log('Unable to determine rewrite target for .htaccess routing.', 'error');
                return ['ok' => false];
            }
            $htaccessPath = $docroot . '/' . trim($basePath, '/') . '/.htaccess';
            $result = $this->patchHtaccess($htaccessPath, $rewriteTarget);
            if (!$result['ok']) {
                $this->log("Failed to configure .htaccess: {$htaccessPath}", 'error');
                if (isset($result['error']) && is_string($result['error'])) {
                    $this->log($result['error'], 'error');
                }
                return ['ok' => false];
            }
            if (($result['changed'] ?? false) === true) {
                $journal[] = ['type' => 'file', 'path' => $htaccessPath, 'backup' => $result['backup'] ?? null];
            }
            $managedHtaccessFiles[] = $this->relativeToProject($htaccessPath);
            $mode = 'htaccess';
        } elseif ($htaccessSupport === 'unknown') {
            if ($rewriteTarget !== null) {
                $htaccessPath = $docroot . '/' . trim($basePath, '/') . '/.htaccess';
                $result = $this->patchHtaccess($htaccessPath, $rewriteTarget);
                if ($result['ok']) {
                    if (($result['changed'] ?? false) === true) {
                        $journal[] = ['type' => 'file', 'path' => $htaccessPath, 'backup' => $result['backup'] ?? null];
                    }
                    $managedHtaccessFiles[] = $this->relativeToProject($htaccessPath);
                    $mode = 'htaccess';
                } else {
                    $manualRequired = true;
                    $this->log("Unable to configure .htaccess automatically: {$htaccessPath}", 'warning');
                    if (isset($result['error']) && is_string($result['error'])) {
                        $this->log($result['error'], 'warning');
                    }
                }
            } else {
                $manualRequired = true;
            }
        } else {
            $manualRequired = true;
            $this->log("Runtime {$runtimeKind} does not support .htaccess routing.", 'warning');
        }

        if ($manualRequired) {
            $manualNotes = $this->manualRoutingHints($runtimeKind, $basePath, $rewriteTarget ?? '/index.php');
            $this->log('Manual routing setup required. Apply one of the snippets below:', 'warning');
            foreach ($manualNotes as $note) {
                $this->log('  ' . $note, 'warning');
            }
        }

        return [
            'ok' => true,
            'mode' => $mode,
            'rewrite_target' => $rewriteTarget ?? '',
            'manual_required' => $manualRequired,
            'manual_notes' => $manualNotes,
            'managed_htaccess_files' => array_values(array_unique($managedHtaccessFiles)),
            'htaccess_configured' => $mode === 'htaccess',
            'journal' => $journal,
        ];
    }

    private function patchHtaccess(string $path, string $rewriteTarget): array
    {
        $source = '';
        $exists = is_file($path);
        if ($exists) {
            $source = file_get_contents($path);
            if (!is_string($source)) {
                return ['ok' => false, 'error' => 'Cannot read existing .htaccess'];
            }
        }

        $block = $this->buildHtaccessBlock($rewriteTarget);
        if (str_contains($source, self::HTACCESS_MARKER_START)) {
            $pattern = '/' . preg_quote(self::HTACCESS_MARKER_START, '/') . '.*?' . preg_quote(self::HTACCESS_MARKER_END, '/') . '\s*/s';
            $patched = preg_replace($pattern, $block, $source, 1);
            if (!is_string($patched)) {
                return ['ok' => false, 'error' => 'Failed to update existing YOURSHIELD .htaccess block'];
            }
        } else {
            $trimmed = rtrim($source);
            $patched = $trimmed === '' ? '' : $trimmed . "\n\n";
            $patched .= $block;
        }

        if ($patched === $source) {
            return ['ok' => true, 'changed' => false];
        }

        $backup = null;
        if ($exists) {
            $backup = $this->createPrivateBackup($path);
            if ($backup === null) {
                return ['ok' => false, 'error' => 'Failed to create .htaccess backup'];
            }
        }

        if (file_put_contents($path, $patched) === false) {
            if ($backup !== null && !$this->restorePrivateBackup($backup, $path)) {
                return ['ok' => false, 'error' => 'Failed to write .htaccess and rollback backup was retained'];
            }
            return ['ok' => false, 'error' => 'Failed to write .htaccess'];
        }

        return ['ok' => true, 'changed' => true, 'backup' => $backup];
    }

    private function unpatchHtaccess(string $path): array
    {
        $source = file_get_contents($path);
        if (!is_string($source)) {
            return ['ok' => false, 'error' => 'Cannot read .htaccess'];
        }

        if (!str_contains($source, self::HTACCESS_MARKER_START)) {
            return ['ok' => true, 'changed' => false];
        }

        $pattern = '/' . preg_quote(self::HTACCESS_MARKER_START, '/') . '.*?' . preg_quote(self::HTACCESS_MARKER_END, '/') . '\s*/s';
        $patched = preg_replace($pattern, '', $source);
        if (!is_string($patched)) {
            return ['ok' => false, 'error' => 'Failed to remove YOURSHIELD .htaccess block'];
        }

        $backup = $this->createPrivateBackup($path);
        if ($backup === null) {
            return ['ok' => false, 'error' => 'Failed to create .htaccess backup'];
        }

        if (file_put_contents($path, $patched) === false) {
            if (!$this->restorePrivateBackup($backup, $path)) {
                return ['ok' => false, 'error' => 'Failed to write cleaned .htaccess and rollback backup was retained'];
            }
            return ['ok' => false, 'error' => 'Failed to write cleaned .htaccess'];
        }

        return ['ok' => true, 'changed' => true, 'backup' => $backup];
    }

    private function buildHtaccessBlock(string $rewriteTarget): string
    {
        $target = '/' . ltrim(trim($rewriteTarget), '/');
        $lines = [
            self::HTACCESS_MARKER_START,
            '<IfModule mod_rewrite.c>',
            '    RewriteEngine On',
            '    RewriteRule ^a/ - [L]',
            '    RewriteCond %{REQUEST_FILENAME} -f [OR]',
            '    RewriteCond %{REQUEST_FILENAME} -d',
            '    RewriteRule ^ - [L]',
            '    RewriteRule ^ ' . $target . ' [L,QSA]',
            '</IfModule>',
            self::HTACCESS_MARKER_END,
        ];
        return implode("\n", $lines) . "\n";
    }

    private function createPrivateBackup(string $path): ?string
    {
        if ($this->backupDir === '' || is_link($this->backupDir)) {
            return null;
        }
        if (!is_dir($this->backupDir) && !mkdir($this->backupDir, 0700, true) && !is_dir($this->backupDir)) {
            return null;
        }

        $name = gmdate('YmdHis') . '-' . bin2hex(random_bytes(6)) . '-' . basename($path);
        $backup = $this->backupDir . '/' . $name;
        if (!copy($path, $backup) || !$this->enforcePosixMode($backup, 0600)) {
            @unlink($backup);
            return null;
        }
        return $backup;
    }

    private function restorePrivateBackup(string $backup, string $path): bool
    {
        $modeSource = is_file($path) ? $path : $backup;
        $permissions = @fileperms($modeSource);
        if ($permissions === false) {
            return false;
        }

        $temporaryPath = $path . '.tmp-' . bin2hex(random_bytes(6));
        if (
            !@copy($backup, $temporaryPath)
            || !$this->enforcePosixMode($temporaryPath, $permissions & 0777)
            || !@rename($temporaryPath, $path)
        ) {
            @unlink($temporaryPath);
            return false;
        }

        clearstatcache(true, $path);
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($path, true);
        }
        return @unlink($backup);
    }

    private function selectPrivateBackupWorkspace(): string
    {
        $name = '.yourshield-installer-'
            . substr(hash('sha256', $this->projectRoot), 0, 12)
            . '-' . bin2hex(random_bytes(6));
        $roots = [sys_get_temp_dir(), dirname($this->projectRoot)];
        $fallback = '';

        foreach (array_unique($roots) as $root) {
            $resolvedRoot = realpath($root);
            $root = rtrim(str_replace('\\', '/', $resolvedRoot !== false ? $resolvedRoot : $root), '/');
            $candidate = ($root === '' ? '/' : $root . '/') . $name;
            if ($this->pathIsInside($this->projectRoot, $candidate)) {
                continue;
            }
            if ($fallback === '') {
                $fallback = $candidate;
            }
            if ($this->pathCanBeCreated($candidate)) {
                return $candidate;
            }
        }

        return $fallback;
    }

    private function cleanupBackupStorage(): bool
    {
        $ok = $this->backupDir !== ''
            && $this->removeManagedTree($this->backupDir, dirname($this->backupDir));
        $legacyBackupDir = $this->yourShieldDir . '/.installer-backups';
        return $this->removeManagedTree($legacyBackupDir, $this->yourShieldDir) && $ok;
    }

    private function cleanupLegacyModuleCache(string $activeCacheDir): bool
    {
        $legacyCacheDir = $this->yourShieldDir . '/cache';
        if ($this->samePath($activeCacheDir, $legacyCacheDir)) {
            return true;
        }
        if ($this->pathHasSymlink($legacyCacheDir)) {
            $this->log("Refused to remove symlinked legacy cache: {$legacyCacheDir}", 'error');
            return false;
        }
        return $this->removeManagedTree($legacyCacheDir, $this->yourShieldDir);
    }

    private function cleanupManagedRuntimeStorage(string $runtimeDir, string $cacheDir, bool $managed): bool
    {
        if (!$managed) {
            return true;
        }

        $expectedRuntimeDir = $this->defaultRuntimeDir();
        $expectedCacheDir = $expectedRuntimeDir . '/cache';
        if (!$this->samePath($runtimeDir, $expectedRuntimeDir) || !$this->samePath($cacheDir, $expectedCacheDir)) {
            return true;
        }
        if ($this->pathHasSymlink($runtimeDir) || $this->pathHasSymlink($cacheDir)) {
            $this->log('Refused to remove symlinked managed runtime storage.', 'error');
            return false;
        }
        if (!$this->removeManagedTree($cacheDir, $runtimeDir)) {
            return false;
        }
        if (is_dir($runtimeDir) && !@rmdir($runtimeDir)) {
            $this->log("Managed runtime root is not empty: {$runtimeDir}", 'error');
            return false;
        }
        return true;
    }

    private function cleanupLegacyPublicBackups(string $docroot): bool
    {
        $projectRoot = realpath($this->projectRoot);
        $publicRoot = realpath($docroot);
        if (is_string($projectRoot) && is_string($publicRoot) && Utils::pathIsInside($publicRoot, $projectRoot)) {
            $publicRoot = $projectRoot;
        }
        if (
            $projectRoot === false
            || $publicRoot === false
            || !is_dir($publicRoot)
            || !$this->pathIsInside($projectRoot, $publicRoot)
        ) {
            $this->log("Refused to scan legacy backups outside project docroot: {$docroot}", 'error');
            return false;
        }

        $candidates = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($publicRoot, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );
            foreach ($iterator as $file) {
                if (!$file instanceof \SplFileInfo || $file->isLink() || !$file->isFile()) {
                    continue;
                }
                if (preg_match('/^.+\.ysbak-[0-9]{14}\z/', $file->getBasename()) !== 1) {
                    continue;
                }
                $path = $file->getPathname();
                $resolved = realpath($path);
                if (
                    $resolved === false
                    || is_link($path)
                    || !$this->pathIsInside($projectRoot, $resolved)
                    || !$this->pathIsInside($publicRoot, $resolved)
                    || !is_writable(dirname($path))
                ) {
                    $this->log("Refused unsafe legacy backup cleanup: {$path}", 'error');
                    return false;
                }
                $candidates[] = $path;
            }
        } catch (\Throwable $e) {
            $this->log('Failed to scan legacy public backups: ' . $e->getMessage(), 'error');
            return false;
        }

        foreach ($candidates as $path) {
            if (is_link($path) || !is_file($path) || !@unlink($path)) {
                $this->log("Failed to remove legacy public backup: {$path}", 'error');
                return false;
            }
        }
        return true;
    }

    private function defaultRuntimeDir(): string
    {
        return rtrim(sys_get_temp_dir(), '/\\')
            . '/.yourshield-runtime-'
            . substr(hash('sha256', str_replace('\\', '/', $this->projectRoot)), 0, 16);
    }

    private function runtimeConfigForOptions(array $options): RuntimeConfig
    {
        $runtime = RuntimeConfig::fromFile($this->configPath);
        $hasRuntimeDir = array_key_exists('runtime_dir', $options);
        $hasCacheDir = array_key_exists('cache_dir', $options);
        $data = $runtime->all();
        $env = $this->discoverEnvironment();
        $data['public_root'] = $env['docroot'];
        $data['mount_path'] = $env['mount_path'];
        $data['application_root'] = $env['application_root'];
        foreach (['site_key', 'secret', 'site_host'] as $key) {
            if (isset($options[$key]) && trim((string) $options[$key]) !== '') {
                $data[$key] = trim((string) $options[$key]);
            }
        }
        if (!empty($options['cloud_url'])) {
            $data['cloud_base_url'] = rtrim(trim((string) $options['cloud_url']), '/');
        }
        if (!$hasRuntimeDir && !$hasCacheDir) {
            return new RuntimeConfig($data);
        }
        if ($hasRuntimeDir) {
            $data['runtime_dir'] = trim((string) $options['runtime_dir']);
            if (!$hasCacheDir) {
                $data['cache_dir'] = rtrim((string) $data['runtime_dir'], '/\\') . '/cache';
            }
        }
        if ($hasCacheDir) {
            $data['cache_dir'] = trim((string) $options['cache_dir']);
        }
        $data['runtime_storage_managed'] = false;
        $configured = new RuntimeConfig($data);
        if (DIRECTORY_SEPARATOR !== '\\') {
            foreach (array_unique([sys_get_temp_dir(), '/tmp', '/var/tmp']) as $temporaryRoot) {
                if (Utils::pathIsInside($temporaryRoot, $configured->getString('runtime_dir'))
                    || Utils::pathIsInside($temporaryRoot, $configured->getString('cache_dir'))
                ) {
                    throw new \InvalidArgumentException(
                        'Explicit runtime storage must stay outside system temp for PrivateTmp compatibility'
                    );
                }
            }
        }
        return $configured;
    }

    private function injectAfterOpenTag(string $source, string $snippet): ?string
    {
        if (!preg_match('/^\s*<\?php\s*(declare\s*\(\s*strict_types\s*=\s*1\s*\)\s*;\s*)?/i', $source, $m)) {
            return null;
        }

        $insertPos = strlen($m[0]);
        return substr($source, 0, $insertPos) . "\n" . $snippet . substr($source, $insertPos);
    }

    private function lintPhpFile(string $path): bool
    {
        try {
            $php = RuntimeConfig::fromFile($this->configPath)->getString('php_cli');
        } catch (\Throwable) {
            $php = '';
        }
        return Utils::lintPhpFile($path, $php);
    }

    private function credentialsLookConfigured(): bool
    {
        if (!is_file($this->configPath)) {
            return false;
        }

        $runtime = RuntimeConfig::fromFile($this->configPath);
        $siteKey = $runtime->getString('site_key');
        $secret = $runtime->getString('secret');
        $cloud = $runtime->getString('cloud_base_url');
        return $siteKey !== '' && $siteKey !== 'replace-with-site-key'
            && $secret !== '' && $secret !== 'replace-with-secret'
            && $cloud !== '' && !str_contains($cloud, 'cloud.example.com');
    }

    private function readLocalConfig(): array
    {
        if (!is_file($this->configLocalPath)) {
            return [];
        }
        $local = require $this->configLocalPath;
        return is_array($local) ? $local : [];
    }

    private function writeLocalConfig(array $local): bool
    {
        ksort($local);

        $content = "<?php\n";
        $content .= "declare(strict_types=1);\n\n";
        $content .= "return " . var_export($local, true) . ";\n";
        $temporaryPath = $this->configLocalPath . '.tmp-' . bin2hex(random_bytes(6));
        $written = $this->configWriter !== null
            ? ($this->configWriter)($temporaryPath, $content)
            : @file_put_contents($temporaryPath, $content, LOCK_EX);
        if (!is_int($written)
            || $written !== strlen($content)
            || !$this->enforcePosixMode($temporaryPath, 0640)
        ) {
            @unlink($temporaryPath);
            return false;
        }
        $storedContent = @file_get_contents($temporaryPath);
        if (!is_string($storedContent)
            || $storedContent !== $content
            || (Utils::resolvePhpCli() !== null && !$this->lintPhpFile($temporaryPath))
        ) {
            @unlink($temporaryPath);
            return false;
        }
        if (!rename($temporaryPath, $this->configLocalPath)) {
            @unlink($temporaryPath);
            return false;
        }

        clearstatcache(true, $this->configLocalPath);
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($this->configLocalPath, true);
        }
        return true;
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

    private function generateBasePath(): string
    {
        $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $length = 12;
        $token = '';
        for ($i = 0; $i < $length; $i++) {
            $token .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }

        return '/assets/.cache/' . $token;
    }

    private function normalizeBasePath(string $basePath): string
    {
        $path = '/' . ltrim(str_replace('\\', '/', trim($basePath)), '/');
        $path = rtrim($path, '/');
        return $path === '' ? '/assets/.cache/' . Utils::randomToken(12) : $path;
    }

    private function basePathStaysInsideDocroot(string $docroot, string $basePath): bool
    {
        $root = realpath($docroot);
        if ($root === false || !is_dir($root) || str_contains($basePath, "\0")) {
            return false;
        }

        $cursor = $root;
        foreach (explode('/', trim(str_replace('\\', '/', $basePath), '/')) as $segment) {
            if ($segment === '') {
                continue;
            }
            if ($segment === '.' || $segment === '..' || str_contains($segment, '?') || str_contains($segment, '#')) {
                return false;
            }

            $cursor .= '/' . $segment;
            if (file_exists($cursor) || is_link($cursor)) {
                $resolved = realpath($cursor);
                if ($resolved === false || !is_dir($resolved) || !$this->pathIsInside($root, $resolved)) {
                    return false;
                }
                $cursor = $resolved;
            }
        }

        return true;
    }

    private function absoluteFromProject(string $path): string
    {
        if (str_starts_with($path, '/')) {
            return $path;
        }
        return $this->projectRoot . '/' . ltrim($path, '/');
    }

    private function resolveProjectFile(string $path, ?string $extension = null): ?string
    {
        $root = realpath($this->projectRoot);
        $resolved = realpath($this->absoluteFromProject(trim($path)));
        if (
            $root === false
            || $resolved === false
            || !is_file($resolved)
            || !$this->pathIsInside($root, $resolved)
        ) {
            return null;
        }
        if ($extension !== null && strtolower((string) pathinfo($resolved, PATHINFO_EXTENSION)) !== $extension) {
            return null;
        }
        return $resolved;
    }

    private function pathIsInside(string $root, string $path): bool
    {
        return Utils::pathIsInside($root, $path);
    }

    private function samePath(string $left, string $right): bool
    {
        if ($left === '' || $right === '') {
            return false;
        }
        $left = Utils::canonicalAbsolutePath($left);
        $right = Utils::canonicalAbsolutePath($right);
        if ($left === null || $right === null) {
            return false;
        }
        if (DIRECTORY_SEPARATOR === '\\') {
            $left = strtolower($left);
            $right = strtolower($right);
        }
        return $left === $right;
    }

    private function managedAssetBase(string $publicRoot, string $basePath): ?string
    {
        $requestedAssetBase = rtrim(str_replace('\\', '/', trim($publicRoot)), '/')
            . '/' . trim(str_replace('\\', '/', $basePath), '/');
        $projectRoot = Utils::canonicalAbsolutePath($this->projectRoot);
        $publicRoot = Utils::canonicalAbsolutePath($publicRoot);
        if (
            $projectRoot === null
            || $publicRoot === null
            || !is_dir($publicRoot)
            || !Utils::pathIsInside($projectRoot, $requestedAssetBase)
            || $this->pathHasSymlink($requestedAssetBase)
            || !$this->basePathStaysInsideDocroot($publicRoot, $basePath)
        ) {
            return null;
        }
        $assetBase = Utils::canonicalAbsolutePath($publicRoot . '/' . trim($basePath, '/'));
        return $assetBase !== null && Utils::pathIsInside($publicRoot, $assetBase) && $assetBase !== $publicRoot
            ? $assetBase
            : null;
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

    private function isFilesystemRoot(string $path): bool
    {
        $path = str_replace('\\', '/', trim($path));
        return $path === '/' || preg_match('/^[A-Za-z]:\/?$/', $path) === 1;
    }

    private function removeManagedTree(string $path, string $allowedRoot): bool
    {
        if (!file_exists($path) && !is_link($path)) {
            return true;
        }

        $root = realpath($allowedRoot);
        if (is_link($path)) {
            $parent = realpath(dirname($path));
            $name = basename(str_replace('\\', '/', $path));
            $candidate = is_string($parent) && $name !== '.' && $name !== '..'
                ? rtrim(str_replace('\\', '/', $parent), '/') . '/' . $name
                : '';
            if (
                $root === false
                || $parent === false
                || $candidate === $root
                || !$this->pathIsInside($root, $parent)
            ) {
                $this->log("Refused to remove symlink outside managed root: {$path}", 'error');
                return false;
            }
            return unlink($path);
        }

        $resolved = realpath($path);
        if (
            $root === false
            || $resolved === false
            || $resolved === $root
            || !$this->pathIsInside($root, $resolved)
        ) {
            $this->log("Refused to remove path outside managed root: {$path}", 'error');
            return false;
        }

        if (is_file($path)) {
            return unlink($path);
        }
        foreach (scandir($path) ?: [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            if (!$this->removeManagedTree($path . '/' . $item, $path)) {
                return false;
            }
        }
        return rmdir($path);
    }

    private function removeEmptyParents(string $path, string $stopAt): void
    {
        $stop = rtrim(str_replace('\\', '/', $stopAt), '/');
        $cursor = rtrim(str_replace('\\', '/', $path), '/');
        while ($cursor !== '' && $cursor !== $stop && $this->pathIsInside($stop, $cursor)) {
            if (!@rmdir($cursor)) {
                return;
            }
            $cursor = dirname($cursor);
        }
    }

    private function relativeToProject(string $absolutePath): string
    {
        if (str_starts_with($absolutePath, $this->projectRoot . '/')) {
            return substr($absolutePath, strlen($this->projectRoot) + 1);
        }
        return $absolutePath;
    }

    private function printChecks(array $checks): void
    {
        foreach ($checks as $check) {
            $label = (string) $check[0];
            $ok = (bool) $check[1];
            $detail = (string) ($check[2] ?? '');
            $status = $ok ? '[OK]' : '[FAIL]';
            $line = "{$status} {$label}";
            if ($detail !== '') {
                $line .= " ({$detail})";
            }
            $this->log($line, 'info');
        }
    }

    private function log(string $message, string $level = 'info'): void
    {
        $message = Utils::redactSecrets($message);

        $record = [
            'level' => $level,
            'message' => $message,
            'time' => gmdate('c'),
        ];
        $this->logs[] = $record;

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

    private function currentCloudUrlPolicy(): array
    {
        if (!is_file($this->configPath)) {
            return [];
        }

        try {
            $runtime = RuntimeConfig::fromFile($this->configPath);
            return $runtime->getArray('cloud_url_policy');
        } catch (\Throwable) {
            return [];
        }
    }

    private function currentTrustedProxyConfig(): array
    {
        if (!is_file($this->configPath)) {
            return [];
        }

        try {
            $runtime = RuntimeConfig::fromFile($this->configPath);
            return $runtime->getArray('trusted_proxy');
        } catch (\Throwable) {
            return [];
        }
    }

    private function mutationOwnerIsValid(): bool
    {
        $issue = Utils::ownershipIssue($this->configLocalPath);
        if ($issue === null) {
            return true;
        }
        $this->log($issue, 'error');
        return false;
    }

    private function currentCacheConfig(): array
    {
        if (!is_file($this->configPath)) {
            return [];
        }

        try {
            $runtime = RuntimeConfig::fromFile($this->configPath);
            return $runtime->getArray('cache');
        } catch (\Throwable) {
            return [];
        }
    }

    private function currentRouteBundleConfig(): array
    {
        $fallback = [
            'current' => [
                'id' => 'bootstrap',
                'challenge_path' => '/c/bootstrap',
                'solve_path' => '/s/bootstrap',
                'session_ingest_path' => '/e/bootstrap',
                'metrics_ingest_path' => '/m/bootstrap',
            ],
            'prev' => null,
        ];

        if (!is_file($this->configPath)) {
            return $fallback;
        }

        try {
            $runtime = RuntimeConfig::fromFile($this->configPath);
            $bundle = $runtime->getArray('route_bundle');
            if (is_array($bundle['current'] ?? null)) {
                return $bundle;
            }
        } catch (\Throwable) {
        }

        return $fallback;
    }

    private function applyTrustedProxyOptions(array $local, array $options): array
    {
        $relevantKeys = [
            'trusted_proxy_provider',
            'trusted_proxy_auto_ips',
            'trusted_proxy_enabled',
            'trusted_proxy_cidrs',
            'trusted_proxy_ip_header',
            'trusted_proxy_proto_header',
        ];
        $hasRelevant = false;
        foreach ($relevantKeys as $key) {
            if (array_key_exists($key, $options)) {
                $hasRelevant = true;
                break;
            }
        }

        if (!$hasRelevant) {
            return ['ok' => true, 'local' => $local];
        }

        $current = $this->currentTrustedProxyConfig();
        $trusted = is_array($local['trusted_proxy'] ?? null) ? $local['trusted_proxy'] : $current;

        $provider = strtolower(trim((string) ($options['trusted_proxy_provider'] ?? ($trusted['provider'] ?? 'none'))));
        if ($provider === '') {
            $provider = 'none';
        }
        if (!in_array($provider, self::CDN_PROVIDERS, true)) {
            $this->log('Unknown trusted_proxy_provider. Allowed: none|cloudflare|cloudfront|fastly', 'error');
            return ['ok' => false, 'local' => $local];
        }

        $enabledDefault = $provider !== 'none';
        $enabled = $this->optionBool($options, 'trusted_proxy_enabled', (bool) ($trusted['enabled'] ?? $enabledDefault));
        $autoIps = $this->optionBool($options, 'trusted_proxy_auto_ips', true);

        $manualRaw = array_key_exists('trusted_proxy_cidrs', $options)
            ? (string) $options['trusted_proxy_cidrs']
            : ($trusted['trusted_cidrs'] ?? []);
        $manualCidrs = $this->normalizeCidrList($manualRaw);

        $providerCidrs = [];
        if ($provider !== 'none' && $autoIps) {
            $providerCidrs = $this->fetchTrustedProxyCidrs($provider);
            if ($providerCidrs === []) {
                $this->log("Failed to fetch trusted proxy CIDRs for provider: {$provider}", 'error');
                return ['ok' => false, 'local' => $local];
            }
            $this->log("Loaded trusted proxy CIDRs from {$provider}: " . count($providerCidrs));
        }

        $allCidrs = $this->normalizeCidrList(array_merge($manualCidrs, $providerCidrs));
        if ($enabled && $allCidrs === []) {
            $this->log('trusted_proxy is enabled but trusted CIDR list is empty', 'error');
            return ['ok' => false, 'local' => $local];
        }

        $ipHeaderDefault = is_string($trusted['ip_header'] ?? null) ? (string) $trusted['ip_header'] : 'HTTP_X_FORWARDED_FOR';
        $protoHeaderDefault = is_string($trusted['proto_header'] ?? null) ? (string) $trusted['proto_header'] : 'HTTP_X_FORWARDED_PROTO';
        $ipHeader = $this->normalizeHeaderName((string) ($options['trusted_proxy_ip_header'] ?? $ipHeaderDefault), 'HTTP_X_FORWARDED_FOR');
        $protoHeader = $this->normalizeHeaderName((string) ($options['trusted_proxy_proto_header'] ?? $protoHeaderDefault), 'HTTP_X_FORWARDED_PROTO');

        $local['trusted_proxy'] = [
            'enabled' => $enabled,
            'trusted_cidrs' => $allCidrs,
            'ip_header' => $ipHeader,
            'proto_header' => $protoHeader,
            'provider' => $provider,
            'auto_ips' => $autoIps,
        ];

        return ['ok' => true, 'local' => $local];
    }

    private function applyCacheOptions(array $local, array $options): array
    {
        $relevantKeys = [
            'cache_driver',
            'cache_prefix',
            'cache_apcu_prefix',
            'cache_lock_wait_ms',
            'cache_lock_ttl_sec',
            'cache_redis_host',
            'cache_redis_port',
            'cache_redis_db',
            'cache_redis_password',
            'cache_redis_timeout_sec',
            'cache_redis_read_timeout_sec',
            'cache_redis_prefix',
        ];

        $hasRelevant = false;
        foreach ($relevantKeys as $key) {
            if (array_key_exists($key, $options)) {
                $hasRelevant = true;
                break;
            }
        }
        if (!$hasRelevant) {
            return ['ok' => true, 'local' => $local];
        }

        $current = $this->currentCacheConfig();
        $cache = is_array($local['cache'] ?? null) ? $local['cache'] : $current;
        $redis = is_array($cache['redis'] ?? null) ? $cache['redis'] : [];

        $driver = strtolower(trim((string) ($options['cache_driver'] ?? ($cache['driver'] ?? 'auto'))));
        if ($driver === '') {
            $driver = 'auto';
        }
        if (!in_array($driver, self::CACHE_DRIVERS, true)) {
            $this->log('Unknown cache_driver. Allowed: auto|file|apcu|redis', 'error');
            return ['ok' => false, 'local' => $local];
        }

        $prefix = trim((string) ($options['cache_prefix'] ?? ($cache['prefix'] ?? 'ys:')));
        if ($prefix === '') {
            $prefix = 'ys:';
        }

        $apcuPrefix = trim((string) ($options['cache_apcu_prefix'] ?? ($cache['apcu_prefix'] ?? $prefix)));
        if ($apcuPrefix === '') {
            $apcuPrefix = $prefix;
        }

        $lockWaitMs = $this->optionInt(
            $options,
            'cache_lock_wait_ms',
            is_numeric($cache['lock_wait_ms'] ?? null) ? (int) $cache['lock_wait_ms'] : 500
        );
        $lockWaitMs = max(1, $lockWaitMs);

        $lockTtlSec = $this->optionInt(
            $options,
            'cache_lock_ttl_sec',
            is_numeric($cache['lock_ttl_sec'] ?? null) ? (int) $cache['lock_ttl_sec'] : 5
        );
        $lockTtlSec = max(1, $lockTtlSec);

        $redisHost = trim((string) ($options['cache_redis_host'] ?? ($redis['host'] ?? '127.0.0.1')));
        if ($redisHost === '') {
            $this->log('cache_redis_host must not be empty', 'error');
            return ['ok' => false, 'local' => $local];
        }

        $redisPort = $this->optionInt(
            $options,
            'cache_redis_port',
            is_numeric($redis['port'] ?? null) ? (int) $redis['port'] : 6379
        );
        if ($redisPort < 1 || $redisPort > 65535) {
            $this->log('cache_redis_port must be in range 1..65535', 'error');
            return ['ok' => false, 'local' => $local];
        }

        $redisDb = $this->optionInt(
            $options,
            'cache_redis_db',
            is_numeric($redis['db'] ?? null) ? (int) $redis['db'] : 0
        );
        if ($redisDb < 0) {
            $this->log('cache_redis_db must be >= 0', 'error');
            return ['ok' => false, 'local' => $local];
        }

        $redisPassword = array_key_exists('cache_redis_password', $options)
            ? (string) $options['cache_redis_password']
            : (string) ($redis['password'] ?? '');

        $redisTimeout = $this->optionFloat(
            $options,
            'cache_redis_timeout_sec',
            is_numeric($redis['timeout_sec'] ?? null) ? (float) $redis['timeout_sec'] : 0.2
        );
        $redisTimeout = max(0.01, $redisTimeout);

        $redisReadTimeout = $this->optionFloat(
            $options,
            'cache_redis_read_timeout_sec',
            is_numeric($redis['read_timeout_sec'] ?? null) ? (float) $redis['read_timeout_sec'] : 0.2
        );
        $redisReadTimeout = max(0.01, $redisReadTimeout);

        $redisPrefix = trim((string) ($options['cache_redis_prefix'] ?? ($redis['prefix'] ?? $prefix)));
        if ($redisPrefix === '') {
            $redisPrefix = $prefix;
        }

        $local['cache'] = [
            'driver' => $driver,
            'prefix' => $prefix,
            'apcu_prefix' => $apcuPrefix,
            'lock_wait_ms' => $lockWaitMs,
            'lock_ttl_sec' => $lockTtlSec,
            'redis' => [
                'host' => $redisHost,
                'port' => $redisPort,
                'db' => $redisDb,
                'password' => $redisPassword,
                'timeout_sec' => $redisTimeout,
                'read_timeout_sec' => $redisReadTimeout,
                'prefix' => $redisPrefix,
            ],
        ];

        return ['ok' => true, 'local' => $local];
    }

    private function fetchTrustedProxyCidrs(string $provider): array
    {
        return match ($provider) {
            'cloudflare' => $this->fetchCloudflareCidrs(),
            'cloudfront' => $this->fetchCloudfrontCidrs(),
            'fastly' => $this->fetchFastlyCidrs(),
            default => [],
        };
    }

    private function fetchCloudflareCidrs(): array
    {
        $v4 = $this->httpGetText('https://www.cloudflare.com/ips-v4');
        $v6 = $this->httpGetText('https://www.cloudflare.com/ips-v6');
        if ($v4 === null || $v6 === null) {
            return [];
        }

        return $this->normalizeCidrList([$v4, $v6]);
    }

    private function fetchCloudfrontCidrs(): array
    {
        $json = $this->httpGetJson('https://ip-ranges.amazonaws.com/ip-ranges.json');
        if (!is_array($json)) {
            return [];
        }

        $services = ['CLOUDFRONT', 'CLOUDFRONT_ORIGIN_FACING'];
        $cidrs = [];

        foreach (($json['prefixes'] ?? []) as $row) {
            if (!is_array($row)) {
                continue;
            }
            $service = strtoupper(trim((string) ($row['service'] ?? '')));
            if (!in_array($service, $services, true)) {
                continue;
            }
            if (is_string($row['ip_prefix'] ?? null)) {
                $cidrs[] = (string) $row['ip_prefix'];
            }
        }

        foreach (($json['ipv6_prefixes'] ?? []) as $row) {
            if (!is_array($row)) {
                continue;
            }
            $service = strtoupper(trim((string) ($row['service'] ?? '')));
            if (!in_array($service, $services, true)) {
                continue;
            }
            if (is_string($row['ipv6_prefix'] ?? null)) {
                $cidrs[] = (string) $row['ipv6_prefix'];
            }
        }

        return $this->normalizeCidrList($cidrs);
    }

    private function fetchFastlyCidrs(): array
    {
        $json = $this->httpGetJson('https://api.fastly.com/public-ip-list');
        if (!is_array($json)) {
            return [];
        }

        $cidrs = [];
        foreach (($json['addresses'] ?? []) as $cidr) {
            if (is_string($cidr)) {
                $cidrs[] = $cidr;
            }
        }
        foreach (($json['ipv6_addresses'] ?? []) as $cidr) {
            if (is_string($cidr)) {
                $cidrs[] = $cidr;
            }
        }

        return $this->normalizeCidrList($cidrs);
    }

    private function httpGetText(string $url): ?string
    {
        $client = new HttpClient();
        $res = $client->request('GET', $url, ['Accept: text/plain'], null, 1000, 5000);
        $status = (int) ($res['status'] ?? 0);
        if ($status < 200 || $status >= 300 || ($res['error'] ?? null) !== null) {
            $this->log("HTTP fetch failed for {$url} (status={$status})", 'error');
            return null;
        }
        return is_string($res['body'] ?? null) ? (string) $res['body'] : null;
    }

    private function httpGetJson(string $url): ?array
    {
        $client = new HttpClient();
        $res = $client->request('GET', $url, ['Accept: application/json'], null, 1000, 5000);
        $status = (int) ($res['status'] ?? 0);
        if ($status < 200 || $status >= 300 || ($res['error'] ?? null) !== null) {
            $this->log("HTTP fetch failed for {$url} (status={$status})", 'error');
            return null;
        }

        $decoded = json_decode((string) ($res['body'] ?? ''), true);
        return is_array($decoded) ? $decoded : null;
    }

    private function normalizeHeaderName(string $raw, string $fallback): string
    {
        $header = strtoupper(trim($raw));
        if ($header === '') {
            return $fallback;
        }

        $header = str_replace('-', '_', $header);
        if (!str_starts_with($header, 'HTTP_')) {
            $header = 'HTTP_' . $header;
        }
        return $header;
    }

    private function normalizeCidrList(mixed $raw): array
    {
        $parts = [];
        if (is_string($raw)) {
            $parts = preg_split('/[\\s,]+/', $raw) ?: [];
        } elseif (is_array($raw)) {
            foreach ($raw as $item) {
                if (is_string($item)) {
                    $sub = preg_split('/[\\s,]+/', $item) ?: [];
                    foreach ($sub as $entry) {
                        $parts[] = $entry;
                    }
                }
            }
        }

        $out = [];
        foreach ($parts as $part) {
            $part = trim((string) $part);
            if ($part === '') {
                continue;
            }

            if (!str_contains($part, '/')) {
                if (filter_var($part, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                    $part .= '/32';
                } elseif (filter_var($part, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                    $part .= '/128';
                } else {
                    continue;
                }
            }

            if (!$this->isValidCidr($part)) {
                continue;
            }
            $out[] = $part;
        }

        return array_values(array_unique($out));
    }

    private function isValidCidr(string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return false;
        }
        [$ip, $prefixRaw] = explode('/', $cidr, 2);
        $ip = trim($ip);
        if ($ip === '' || $prefixRaw === '' || !ctype_digit($prefixRaw)) {
            return false;
        }

        $prefix = (int) $prefixRaw;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $prefix >= 0 && $prefix <= 32;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $prefix >= 0 && $prefix <= 128;
        }
        return false;
    }

    private function probeModuleRoutes(
        string $probeUrl,
        string $basePath,
        array $routeBundle,
        string $siteHost = ''
    ): array
    {
        $origin = $this->normalizeProbeOrigin($probeUrl);
        if ($origin === null) {
            return [['probe_url valid', false, 'invalid probe url']];
        }
        $siteHost = Utils::canonicalHost($siteHost);
        $hostHeader = $siteHost !== '' ? ['Host: ' . $siteHost] : [];

        $healthUrl = rtrim($origin, '/') . rtrim($basePath, '/') . '/health';
        $challengePath = is_string($routeBundle['current']['challenge_path'] ?? null)
            ? (string) $routeBundle['current']['challenge_path']
            : '/c/bootstrap';
        $challengeRoute = Utils::joinBaseAndRoute($basePath, $challengePath);
        $challengeUrl = rtrim($origin, '/') . $challengeRoute . '?rid=probe-' . Utils::randomToken(8);

        $client = new HttpClient();
        $healthRes = $client->request(
            'GET',
            $healthUrl,
            array_merge(['Accept: application/json'], $hostHeader),
            null,
            1000,
            5000
        );
        $healthStatus = (int) ($healthRes['status'] ?? 0);
        $healthOk = $healthStatus === 200;
        if ($healthOk) {
            $decoded = json_decode((string) ($healthRes['body'] ?? ''), true);
            $healthOk = is_array($decoded) && (($decoded['ok'] ?? false) === true);
        }

        $challengeRes = $client->request(
            'GET',
            $challengeUrl,
            array_merge(['Accept: text/html'], $hostHeader),
            null,
            1000,
            5000
        );
        $challengeStatus = (int) ($challengeRes['status'] ?? 0);
        $challengeOk = in_array($challengeStatus, [404, 429], true);

        return [
            ['probe health endpoint', $healthOk, 'status=' . $healthStatus . ' ' . $healthUrl],
            ['probe challenge route', $challengeOk, 'status=' . $challengeStatus . ' ' . $challengeRoute],
        ];
    }

    private function probeLiveIntegration(
        RuntimeConfig $runtime,
        string $probeUrl,
        string $basePath,
        array $routeBundle,
        string $assetRoot
    ): array {
        $origin = $this->normalizeProbeOrigin($probeUrl);
        if ($origin === null) {
            return [['probe_url valid', false, 'invalid probe url']];
        }

        $siteHost = Utils::resolveSiteHost([], $runtime->getString('site_host'));
        $cloud = new CloudClient($runtime, new HttpClient(), new HmacSigner());
        $manifest = $cloud->assetsManifest([
            'api_ver' => $runtime->getString('api_ver', '1'),
            'site_key' => $runtime->getString('site_key'),
            'host' => $siteHost !== '' ? $siteHost : null,
            'base_path' => $basePath,
        ]);

        $current = $assetRoot . '/current';
        $resolvedAssetRoot = realpath($assetRoot);
        $bundleId = AssetUpdater::activeBundleId($assetRoot) ?? '';
        $resolvedCurrent = $bundleId !== '' ? realpath($assetRoot . '/' . $bundleId) : false;
        $activeBundleOk = $bundleId !== ''
            && preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}[a-zA-Z0-9]\z/', $bundleId) === 1
            && is_string($resolvedCurrent)
            && is_dir($resolvedCurrent)
            && is_string($resolvedAssetRoot)
            && dirname($resolvedCurrent) === $resolvedAssetRoot
            && is_file($resolvedCurrent . '/.bundle-manifest.json');

        $home = (new HttpClient())->request(
            'GET',
            rtrim($origin, '/') . '/',
            array_merge(['Accept: text/html'], $siteHost !== '' ? ['Host: ' . $siteHost] : []),
            null,
            1000,
            5000
        );
        $homeStatus = (int) ($home['status'] ?? 0);
        $homeOk = ($homeStatus >= 200 && $homeStatus < 400) || $homeStatus === 403;

        return array_merge([
            ['cloud authorization', ($manifest['ok'] ?? false) === true, 'status=' . (int) ($manifest['status'] ?? 0)],
            ['active asset bundle', $activeBundleOk, $current],
            ['probe home response', $homeOk, 'status=' . $homeStatus . ' ' . $origin . '/'],
        ], $this->probeModuleRoutes($probeUrl, $basePath, $routeBundle, $siteHost));
    }

    private function normalizeProbeOrigin(string $probeUrl): ?string
    {
        $probeUrl = trim($probeUrl);
        if ($probeUrl === '') {
            return null;
        }

        $parts = parse_url($probeUrl);
        if ($parts === false) {
            return null;
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = (string) ($parts['host'] ?? '');
        if (($scheme !== 'http' && $scheme !== 'https') || $host === ''
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || !in_array($parts['path'] ?? '', ['', '/'], true)
        ) {
            return null;
        }

        $origin = $scheme . '://' . $host;
        if (isset($parts['port']) && is_numeric($parts['port'])) {
            $origin .= ':' . (int) $parts['port'];
        }
        return $origin;
    }

    private function normalizeRuntimeOption(mixed $raw): ?string
    {
        $runtime = strtolower(trim((string) $raw));
        if ($runtime === '') {
            return 'auto';
        }
        if ($runtime === 'auto') {
            return 'auto';
        }
        return in_array($runtime, self::RUNTIME_ENVIRONMENTS, true) ? $runtime : null;
    }

    private function detectRuntimeEnvironment(string $runtimeOverride, string $docroot): array
    {
        $runtime = $this->normalizeRuntimeOption($runtimeOverride) ?? 'auto';
        $serverSoftware = trim((string) ($_SERVER['SERVER_SOFTWARE'] ?? ''));
        $detectedBy = 'auto';

        if ($runtime !== 'auto') {
            $kind = $runtime;
            $detectedBy = 'option';
        } elseif (PHP_SAPI === 'cli-server') {
            $kind = 'php_builtin';
            $detectedBy = 'php_sapi';
        } elseif ($serverSoftware !== '') {
            $kind = $this->detectRuntimeFromServerSoftware($serverSoftware);
            $detectedBy = 'server_software';
        } else {
            $kind = $this->detectRuntimeFromFilesystem($docroot);
            $detectedBy = 'filesystem';
        }

        $htaccessSupport = $this->resolveHtaccessSupport($kind, $docroot);

        return [
            'kind' => $kind,
            'detected_by' => $detectedBy,
            'server_software' => $serverSoftware,
            'htaccess_support' => $htaccessSupport,
            'supports_htaccess' => $htaccessSupport === 'supported',
        ];
    }

    private function detectRuntimeFromServerSoftware(string $serverSoftware): string
    {
        $software = strtolower($serverSoftware);
        if (str_contains($software, 'litespeed')) {
            return 'litespeed';
        }
        if (str_contains($software, 'apache')) {
            return 'apache';
        }
        if (str_contains($software, 'nginx') || str_contains($software, 'openresty')) {
            return 'nginx';
        }
        if (str_contains($software, 'caddy')) {
            return 'caddy';
        }
        if (str_contains($software, 'iis')) {
            return 'iis';
        }
        return 'unknown';
    }

    private function detectRuntimeFromFilesystem(string $docroot): string
    {
        $docroot = rtrim($docroot, '/');
        if (($docroot !== '' && is_file($docroot . '/.htaccess')) || is_file($this->projectRoot . '/.htaccess')) {
            return 'apache';
        }
        if (($docroot !== '' && is_file($docroot . '/web.config')) || is_file($this->projectRoot . '/web.config')) {
            return 'iis';
        }
        if (($docroot !== '' && is_file($docroot . '/Caddyfile')) || is_file($this->projectRoot . '/Caddyfile')) {
            return 'caddy';
        }
        if (($docroot !== '' && is_file($docroot . '/nginx.conf')) || is_file($this->projectRoot . '/nginx.conf')) {
            return 'nginx';
        }
        return 'unknown';
    }

    private function resolveHtaccessSupport(string $runtimeKind, string $docroot): string
    {
        if (in_array($runtimeKind, self::RUNTIME_HTACCESS_SUPPORTED, true)) {
            return 'supported';
        }
        if (in_array($runtimeKind, self::RUNTIME_HTACCESS_UNSUPPORTED, true)) {
            return 'unsupported';
        }

        $docroot = rtrim($docroot, '/');
        if (($docroot !== '' && is_file($docroot . '/.htaccess')) || is_file($this->projectRoot . '/.htaccess')) {
            return 'supported';
        }
        return 'unknown';
    }

    private function resolveRewriteTarget(array $entrypoints, string $docroot): ?string
    {
        $docroot = rtrim($docroot, '/');
        if ($docroot === '') {
            return null;
        }

        $best = null;
        foreach ($entrypoints as $entrypoint) {
            if (!is_string($entrypoint) || $entrypoint === '') {
                continue;
            }
            if (!str_starts_with($entrypoint, $docroot . '/')) {
                continue;
            }

            $relative = '/' . ltrim(substr($entrypoint, strlen($docroot)), '/');
            if ($relative === '/' || $relative === '') {
                continue;
            }

            if ($relative === '/index.php') {
                return $relative;
            }
            if ($best === null || strlen($relative) < strlen($best)) {
                $best = $relative;
            }
        }

        return $best;
    }

    private function manualRoutingHints(string $runtimeKind, string $basePath, string $rewriteTarget): array
    {
        $base = $this->normalizeBasePath($basePath);
        $baseNoSlash = ltrim($base, '/');
        $target = '/' . ltrim(trim($rewriteTarget), '/');

        return match ($runtimeKind) {
            'nginx' => [
                'Nginx:',
                'location ^~ ' . $base . '/a/ { try_files $uri =404; }',
                'location ^~ ' . $base . '/ { try_files $uri $uri/ ' . $target . '?$query_string; }',
            ],
            'iis' => [
                'IIS (web.config rewrite rule):',
                '<match url="^' . $baseNoSlash . '/(.*)$" ignoreCase="true" />',
                '<add input="{REQUEST_URI}" pattern="^' . preg_quote($base, '/') . '/a/" negate="true" />',
                '<action type="Rewrite" url="' . ltrim($target, '/') . '" appendQueryString="true" />',
            ],
            'caddy' => [
                'Caddy:',
                '@ys_dynamic path ' . $base . '/*',
                '@ys_static path ' . $base . '/a/*',
                'rewrite @ys_dynamic ' . $target,
                'handle @ys_static { file_server }',
            ],
            'php_builtin' => [
                'PHP built-in server does not process .htaccess.',
                'Use a router script and forward dynamic requests under ' . $base . ' to ' . $target . '.',
                'Keep static assets under ' . $base . '/a/ served from disk.',
            ],
            default => [
                'Configure web server rewrite for prefix ' . $base . ' to ' . $target . '.',
                'Exclude static assets under ' . $base . '/a/ from rewrite and return 404 for missing files.',
            ],
        };
    }

    private function basePathFromConfigFallback(): string
    {
        if (!is_file($this->configPath)) {
            return $this->generateBasePath();
        }

        try {
            $runtime = RuntimeConfig::fromFile($this->configPath);
            $configured = trim($runtime->getString('base_path'));
            if ($configured !== '') {
                $normalized = $this->normalizeBasePath($configured);
                if ($normalized !== '/assets/.cache/ys_demo') {
                    return $normalized;
                }
            }
        } catch (\Throwable) {
        }

        return $this->generateBasePath();
    }

    private function detectCms(): string
    {
        if (is_file($this->projectRoot . '/wp-config.php') || is_dir($this->projectRoot . '/wp-includes')) {
            return 'wordpress';
        }
        if (is_file($this->projectRoot . '/artisan') && is_file($this->projectRoot . '/bootstrap/app.php')) {
            return 'laravel';
        }
        if (is_file($this->projectRoot . '/bin/console') && is_file($this->projectRoot . '/config/bundles.php')) {
            return 'symfony';
        }
        return 'generic';
    }

    private function resolveCms(string $requestedCms, array $env): string
    {
        $allowed = ['wordpress', 'laravel', 'symfony', 'generic'];
        if (in_array($requestedCms, $allowed, true)) {
            return $requestedCms;
        }
        return in_array((string) ($env['cms'] ?? ''), $allowed, true) ? (string) $env['cms'] : 'generic';
    }

    private function entrypointsForCms(string $docroot, string $cms): array
    {
        $candidates = [];
        if ($cms === 'wordpress') {
            $candidates[] = $this->projectRoot . '/index.php';
            $candidates[] = $this->projectRoot . '/wp-login.php';
            $candidates[] = $docroot . '/index.php';
            $candidates[] = $docroot . '/wp-login.php';
        } elseif ($cms === 'laravel' || $cms === 'symfony') {
            $candidates[] = $this->projectRoot . '/public/index.php';
            $candidates[] = $docroot . '/index.php';
        } else {
            $candidates[] = $docroot . '/index.php';
            $candidates[] = $this->projectRoot . '/index.php';
        }

        $entrypoints = [];
        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                $entrypoints[] = $candidate;
            }
        }

        return array_values(array_unique($entrypoints));
    }

    private function applyCmsPresets(array $local, string $cms): array
    {
        $presets = $this->cmsPresets($cms);
        if ($presets === []) {
            return $local;
        }

        $runtime = RuntimeConfig::fromFile($this->configPath);
        $baseExcluded = $runtime->getArray('excluded_path_prefixes');
        $baseStrict = $runtime->getArray('strict_path_prefixes');

        $existingExcluded = is_array($local['excluded_path_prefixes'] ?? null) ? $local['excluded_path_prefixes'] : [];
        $existingStrict = is_array($local['strict_path_prefixes'] ?? null) ? $local['strict_path_prefixes'] : [];

        $local['excluded_path_prefixes'] = $this->mergePrefixLists($baseExcluded, $existingExcluded, $presets['excluded_path_prefixes'] ?? []);
        $local['strict_path_prefixes'] = $this->mergePrefixLists($baseStrict, $existingStrict, $presets['strict_path_prefixes'] ?? []);

        return $local;
    }

    private function cmsPresets(string $cms): array
    {
        return match ($cms) {
            'wordpress' => [
                'excluded_path_prefixes' => [
                    // Machine endpoints need an explicit verified caller policy, never an automatic bypass.
                ],
                'strict_path_prefixes' => [
                    '/wp-login.php',
                    '/wp-admin',
                ],
            ],
            'laravel' => [
                'excluded_path_prefixes' => [
                    '/storage',
                    '/vendor',
                    '/build',
                ],
                'strict_path_prefixes' => [
                    '/login',
                    '/admin',
                ],
            ],
            'symfony' => [
                'excluded_path_prefixes' => [
                    '/build',
                    '/bundles',
                ],
                'strict_path_prefixes' => [
                    '/login',
                    '/admin',
                ],
            ],
            default => [
                'excluded_path_prefixes' => [],
                'strict_path_prefixes' => [],
            ],
        };
    }

    private function mergePrefixLists(array ...$lists): array
    {
        $merged = [];
        foreach ($lists as $list) {
            foreach ($list as $prefix) {
                if (!is_string($prefix)) {
                    continue;
                }
                $prefix = trim($prefix);
                if ($prefix === '') {
                    continue;
                }
                if (!str_starts_with($prefix, '/')) {
                    $prefix = '/' . $prefix;
                }
                $normalized = rtrim($prefix, '/');
                $merged[$normalized === '' ? '/' : $normalized] = true;
            }
        }
        return array_keys($merged);
    }

    private function optionBool(array $options, string $key, bool $default): bool
    {
        if (!array_key_exists($key, $options)) {
            return $default;
        }
        $value = $options[$key];
        if (is_bool($value)) {
            return $value;
        }
        if (is_string($value) || is_int($value)) {
            return filter_var((string) $value, FILTER_VALIDATE_BOOLEAN);
        }
        return $default;
    }

    private function optionInt(array $options, string $key, int $default): int
    {
        if (!array_key_exists($key, $options)) {
            return $default;
        }
        $value = $options[$key];
        return is_numeric($value) ? (int) $value : $default;
    }

    private function optionFloat(array $options, string $key, float $default): float
    {
        if (!array_key_exists($key, $options)) {
            return $default;
        }
        $value = $options[$key];
        return is_numeric($value) ? (float) $value : $default;
    }

    private function normalizeBotBlockMode(mixed $raw): ?string
    {
        $mode = strtolower(trim((string) $raw));
        if ($mode === '') {
            return 'block';
        }
        return in_array($mode, self::BOT_BLOCK_MODES, true) ? $mode : null;
    }

    private function mountedBasePath(string $path, string $mount): string
    {
        $path = $this->normalizeBasePath($path);
        return $mount !== '' && !str_starts_with($path, $mount . '/') ? $mount . $path : $path;
    }

    private function integrationMethod(array $options, array $env, array $entrypoints): string
    {
        $method = (string) ($options['integration_method'] ?? $this->readLocalConfig()['integration']['method'] ?? 'auto');
        if ($method !== 'auto') {
            return $method;
        }
        if ($entrypoints === [] && (is_file($env['application_root'] . '/index.html') || is_file($env['application_root'] . '/index.htm'))) {
            return 'static';
        }
        if (in_array(PHP_SAPI, ['cgi-fcgi', 'fpm-fcgi', 'apache2handler'], true)) {
            return 'prepend';
        }
        return Utils::resolvePhpCli() !== null ? 'entrypoint' : 'manual';
    }

    private function coverageDescription(string $method): string
    {
        return match ($method) {
            'prepend' => 'PHP entrypoints in the configured directory; direct static delivery still requires web-server protection.',
            'static' => 'HTML documents through the gateway; explicitly served resources remain static.',
            'entrypoint' => 'Only the listed PHP entrypoints. CMS updates can replace these files; verify coverage after upgrades.',
            default => 'Only requests reaching the manually connected bootstrap; verification is required.',
        };
    }

    private function checkConnection(RuntimeConfig $runtime, array $options = []): array
    {
        foreach (['site_key', 'secret'] as $key) {
            $value = trim($runtime->getString($key));
            if ($value === '' || str_starts_with($value, 'replace-with-')) {
                return ['ok' => false, 'detail' => 'Site credentials must be configured before installation.'];
            }
        }
        if ($this->connectionProbe !== null) {
            return ($this->connectionProbe)($runtime, $options);
        }
        $host = Utils::resolveSiteHost($_SERVER, $runtime->getString('site_host'));
        if ($host === '') {
            return ['ok' => false, 'detail' => 'A canonical site_host is required.'];
        }
        $cloud = new CloudClient($runtime, new HttpClient(), new HmacSigner());
        $response = $cloud->handshake([
            'api_ver' => '1', 'site_key' => $runtime->getString('site_key'), 'host' => $host,
        ]);
        $status = (int) ($response['status'] ?? 0);
        $prefix = 'Site handshake failed (HTTP ' . $status . '). ';
        if (($response['ok'] ?? false) !== true) {
            $curlCode = (int) ($response['error_code'] ?? 0);
            if ($curlCode !== 0) {
                $hint = match ($curlCode) {
                    CURLE_COULDNT_RESOLVE_HOST => 'Cloud API DNS lookup failed on this host.',
                    CURLE_COULDNT_CONNECT => 'Could not connect to the cloud API. Check outbound HTTPS and firewall rules.',
                    CURLE_OPERATION_TIMEDOUT => 'Cloud API request timed out. Check connectivity and request timeouts.',
                    CURLE_SSL_CONNECT_ERROR => 'Cloud API TLS handshake failed. Check the hosting TLS configuration.',
                    CURLE_SSL_CACERT, CURLE_SSL_CACERT_BADFILE => 'Cloud API certificate verification failed. Check the hosting CA certificate store and server clock.',
                    default => 'Cloud API transport failed. Check the hosting cURL configuration.',
                };
                return ['ok' => false, 'detail' => $prefix . 'cURL ' . $curlCode . ': ' . $hint];
            }
            $hint = match ($status) {
                0 => 'No complete HTTP response. Check cloud_base_url, outbound HTTPS, DNS, TLS certificates and request timeouts.',
                401 => 'Check Site activation, site_key/secret, allowed site_host and server clock synchronization.',
                403 => 'Check Site access and cloud API proxy/firewall rules.',
                404, 405 => 'Check cloud_base_url and deploy the cloud API backend supporting PHP module 1.1.0 (POST /v1/site/handshake).',
                429 => 'Cloud API rate limit reached. Wait and retry installation.',
                default => 'Check the cloud API backend and reverse proxy logs.',
            };
            return ['ok' => false, 'detail' => $prefix . $hint];
        }
        $data = (array) ($response['data'] ?? []);
        if (($data['ok'] ?? false) !== true) {
            return ['ok' => false, 'detail' => $prefix . 'Cloud API returned an invalid or rejected handshake. Check cloud_base_url and reverse proxy routing.'];
        }
        if (($data['api_ver'] ?? '') !== '1') {
            return ['ok' => false, 'detail' => $prefix . 'Unsupported api_ver; expected 1. Update the cloud API backend.'];
        }
        if (!is_string($data['site_host'] ?? null) || Utils::canonicalHost($data['site_host']) !== $host) {
            return ['ok' => false, 'detail' => $prefix . 'Returned site_host does not match the configured Site host. Check Site domain settings and cloud API routing.'];
        }
        $missing = [];
        foreach (['installer_probe' => true, 'request_gate' => 'all-methods', 'browser_proof' => true] as $capability => $expected) {
            if (($data['capabilities'][$capability] ?? null) !== $expected) {
                $missing[] = $capability;
            }
        }
        if ($missing !== []) {
            return ['ok' => false, 'detail' => $prefix . 'Required capabilities unavailable: ' . implode(', ', $missing) . '. Update the cloud API backend for PHP module 1.1.0.'];
        }
        return ['ok' => true, 'detail' => 'Site handshake verified.'];
    }

    private function configureIntegration(string $method, array $env, array $local, array &$journal): ?array
    {
        $result = ['method' => $method, 'files' => [], 'notes' => []];
        if (Utils::resolvePhpCli() === null) {
            $result['notes'][] = 'No background shell is available. Use authenticated web maintenance; module updates require the native compiler validation endpoint.';
        }
        $root = $env['application_root'];
        if ($method === 'prepend') {
            $kind = (string) ($this->environmentOptions['prepend_config'] ?? (PHP_SAPI === 'apache2handler' ? 'htaccess' : 'user_ini'));
            if (!in_array($kind, ['user_ini', 'htaccess'], true)) {
                $this->log('prepend_config must be user_ini or htaccess.', 'error');
                return null;
            }
            $path = $root . ($kind === 'htaccess' ? '/.htaccess' : '/.user.ini');
            $prefix = $kind === 'htaccess' ? '#' : ';';
            $old = is_file($path) ? (string) file_get_contents($path) : '';
            $without = $this->stripIntegrationBlock($old, 'PREPEND', $prefix);
            if (preg_match('/^\s*(?:php_(?:admin_)?value\s+)?auto_prepend_file\s*(?:=|\s)\s*["\']?[^\s"\';#]/mi', $without)) {
                $this->log('Existing auto_prepend_file belongs to another integration. Use manual mode to preserve its chain.', 'error');
                return null;
            }
            $shim = str_replace('\\', '/', $this->yourShieldDir . '/prepend.php');
            if (str_contains($shim, '"') || str_contains($shim, "\n")) {
                return null;
            }
            $directive = $kind === 'htaccess' ? 'php_value auto_prepend_file ' : 'auto_prepend_file = ';
            $content = rtrim($without) . "\n{$prefix} YOURSHIELD-PREPEND-START\n"
                . $directive . '"' . $shim . '"' . "\n{$prefix} YOURSHIELD-PREPEND-END\n";
            if (!$this->writeIntegrationFile($path, $content, $journal)) {
                return null;
            }
            $result['files'][] = ['path' => $this->relativeToProject($path), 'block' => 'PREPEND', 'prefix' => $prefix];
            $result['notes'][] = $kind === 'user_ini'
                ? 'PHP-FPM/CGI must apply .user.ini. Workers may cache the previous setting for ' . max(300, (int) ini_get('user_ini.cache_ttl')) . ' seconds; verify after propagation.'
                : 'php_value requires Apache mod_php. Verify the PHP handler and every PHP entrypoint.';
        } elseif ($method === 'static') {
            $gateway = $root . '/ys-gateway.php';
            $content = "<?php\n// YOURSHIELD-GATEWAY\nrequire " . var_export($this->yourShieldDir . '/gateway.php', true) . ";\n";
            if (is_file($gateway) && !str_contains((string) file_get_contents($gateway), '// YOURSHIELD-GATEWAY')) {
                $this->log('ys-gateway.php already belongs to the application.', 'error');
                return null;
            }
            if (!$this->writeIntegrationFile($gateway, $content, $journal)) {
                return null;
            }
            $result['files'][] = ['path' => $this->relativeToProject($gateway), 'block' => 'GATEWAY', 'prefix' => '//'];
            if (($env['runtime']['htaccess_support'] ?? '') === 'supported') {
                $path = $root . '/.htaccess';
                $old = is_file($path) ? (string) file_get_contents($path) : '';
                $without = $this->stripIntegrationBlock($old, 'STATIC', '#');
                $block = "# YOURSHIELD-STATIC-START\nDirectoryIndex ys-gateway.php\nRewriteEngine On\n"
                    . "RewriteRule ^ys-gateway\\.php$ - [L]\n"
                    . "RewriteRule \\.html?$ " . $env['mount_path'] . "/ys-gateway.php [NC,L,QSA]\n"
                    . "RewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ " . $env['mount_path'] . "/ys-gateway.php [L,QSA]\n"
                    . "# YOURSHIELD-STATIC-END\n";
                if (!$this->writeIntegrationFile($path, $block . ltrim($without), $journal)) {
                    return null;
                }
                $result['files'][] = ['path' => $this->relativeToProject($path), 'block' => 'STATIC', 'prefix' => '#'];
            } else {
                $result['notes'][] = 'Configure the web server to route HTML documents and directory/deep paths to '
                    . $env['mount_path'] . '/ys-gateway.php, preserve the request URI/query, and keep selected resources static.';
                if (($env['runtime']['kind'] ?? '') === 'nginx') {
                    $mount = $env['mount_path'];
                    $result['notes'][] = 'Nginx: location ' . ($mount === '' ? '/' : $mount . '/')
                        . ' { try_files $uri ' . $mount . '/ys-gateway.php?$query_string; }';
                    $result['notes'][] = 'Nginx: location ~* ^' . preg_quote($mount, '~')
                        . '/.*\\.html?$ { rewrite ^ ' . $mount . '/ys-gateway.php last; }';
                }
            }
        } elseif ($method === 'manual') {
            $result['notes'][] = "Connect before the application: require_once " . var_export($this->yourShieldDir . '/prepend.php', true) . ';';
        }
        // Remove old managed integration blocks only after replacement files were staged.
        foreach (($local['enabled'] ?? false) ? [] : (array) ($local['integration']['files'] ?? []) as $oldFile) {
            if (!is_array($oldFile) || in_array($oldFile, $result['files'], true)) {
                continue;
            }
            if (!$this->removeIntegrationFile($oldFile, $journal)) {
                return null;
            }
        }
        return $result;
    }

    private function stripIntegrationBlock(string $source, string $block, string $prefix): string
    {
        return (string) preg_replace('~^' . preg_quote($prefix . ' YOURSHIELD-' . $block . '-START', '~')
            . '.*?^' . preg_quote($prefix . ' YOURSHIELD-' . $block . '-END', '~') . '[^\r\n]*\r?\n?~ms', '', $source);
    }

    private function writeIntegrationFile(string $path, string $content, array &$journal): bool
    {
        if (!Utils::pathIsInside($this->projectRoot, $path) || $this->pathHasSymlink($path)) {
            $this->log('Refused unsafe integration file.', 'error');
            return false;
        }
        $backup = is_file($path) ? $this->createPrivateBackup($path) : null;
        if (is_file($path) && $backup === null) {
            return false;
        }
        $journal[] = ['type' => 'file', 'path' => $path, 'backup' => $backup];
        $temporary = $path . '.tmp-' . bin2hex(random_bytes(6));
        if (@file_put_contents($temporary, $content, LOCK_EX) !== strlen($content)
            || @file_get_contents($temporary) !== $content || !@chmod($temporary, 0644)
            || !@rename($temporary, $path)
        ) {
            @unlink($temporary);
            return false;
        }
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($path, true);
        }
        return true;
    }

    private function removeIntegrationFile(array $file, array &$journal): bool
    {
        $path = $this->resolveProjectFile((string) ($file['path'] ?? ''));
        if ($path === null) {
            return true;
        }
        $source = (string) file_get_contents($path);
        if (($file['block'] ?? '') === 'GATEWAY') {
            // Preserve the stable file while old worker/rewrite configuration can still point to it.
            return true;
        }
        if (!in_array($file['block'] ?? '', ['PREPEND', 'STATIC'], true)
            || !in_array($file['prefix'] ?? '', ['#', ';'], true)
        ) {
            return false;
        }
        return $this->writeIntegrationFile($path,
            $this->stripIntegrationBlock($source, $file['block'], $file['prefix']), $journal);
    }

    private function prepareNativeValidator(array &$local, string $origin, array &$journal): bool
    {
        $path = rtrim((string) ($local['application_root'] ?? ''), '/') . '/ys-validate.php';
        $content = "<?php\n// YOURSHIELD-VALIDATOR\nrequire " . var_export($this->yourShieldDir . '/validator.php', true) . ";\n";
        if (is_file($path) && !str_contains((string) file_get_contents($path), '// YOURSHIELD-VALIDATOR')) {
            $this->log('ys-validate.php already belongs to the application.', 'error');
            return false;
        }
        if ((is_link($path) || !is_file($path) || file_get_contents($path) !== $content)
            && !$this->writeIntegrationFile($path, $content, $journal)
        ) {
            return false;
        }
        $local['module_update']['validator_url'] = $origin . (string) ($local['mount_path'] ?? '') . '/ys-validate.php';
        $local['module_update']['validator_token'] = bin2hex(random_bytes(32));
        return true;
    }

    private function verifyAndActivate(string $probeUrl, ?array $candidate = null): int
    {
        if (!$this->mutationOwnerIsValid()) {
            return 1;
        }
        $previousLive = $this->readLocalConfig();
        $local = $candidate ?? $previousLive;
        $runtime = new RuntimeConfig(array_replace_recursive(RuntimeConfig::fromFile($this->configPath)->all(), $local));
        $connection = $this->checkConnection($runtime);
        if (!$connection['ok']) {
            $this->log($connection['detail'], 'error');
            return 2;
        }
        $origin = $this->normalizeProbeOrigin($probeUrl);
        $host = Utils::canonicalHost((string) parse_url($probeUrl, PHP_URL_HOST));
        $configuredHost = Utils::canonicalHost($runtime->getString('site_host'));
        if ($origin === null || $host === '' || $host !== $configuredHost) {
            $this->log('Verification requires an authenticated Site connection and its exact origin.', 'error');
            return 2;
        }
        $validatorJournal = [];
        if (!$this->prepareNativeValidator($local, $origin, $validatorJournal)) {
            $this->rollbackInstall($validatorJournal);
            return 2;
        }
        $token = bin2hex(random_bytes(32));
        $local['installation']['probe_hash'] = hash('sha256', $token);
        $local['installation']['probe_expires_at'] = time() + 120;
        $probeConfig = $candidate === null ? $local : $previousLive;
        $probeConfig['installation']['probe_hash'] = $local['installation']['probe_hash'];
        $probeConfig['installation']['probe_expires_at'] = $local['installation']['probe_expires_at'];
        if (!$this->writeLocalConfig($probeConfig)) {
            return 1;
        }
        $paths = [(string) ($local['base_path'] ?? '') . '/health'];
        $method = (string) ($local['integration']['method'] ?? 'entrypoint');
        $root = (string) ($local['public_root'] ?? '');
        foreach ((array) ($local['managed_entrypoints'] ?? []) as $entry) {
            $absolute = $this->resolveProjectFile((string) $entry);
            if ($absolute !== null && Utils::pathIsInside($root, $absolute)) {
                $paths[] = '/' . ltrim(substr($absolute, strlen($root)), '/');
            }
        }
        $paths[] = rtrim((string) ($local['mount_path'] ?? ''), '/') . '/';
        $sentinel = null;
        if ($method === 'prepend') {
            $sentinel = rtrim((string) $local['application_root'], '/') . '/ys-probe-' . bin2hex(random_bytes(12)) . '.php';
            if (@file_put_contents($sentinel, '<?php http_response_code(404);', LOCK_EX) === false) {
                unset($local['installation']['probe_hash'], $local['installation']['probe_expires_at']);
                $this->writeLocalConfig($candidate === null ? $local : $previousLive);
                return 2;
            }
            $paths[] = '/' . ltrim(substr($sentinel, strlen($root)), '/');
        } elseif ($method === 'static') {
            // A real existing HTML file must reach the gateway; probing only PHP/root
            // can be satisfied by a previous prepend or front-controller integration.
            $sentinel = rtrim((string) $local['application_root'], '/') . '/ys-probe-' . bin2hex(random_bytes(12)) . '.HtMl';
            if (@file_put_contents($sentinel, '<html>installer routing probe</html>', LOCK_EX) === false) {
                unset($local['installation']['probe_hash'], $local['installation']['probe_expires_at']);
                $this->writeLocalConfig($candidate === null ? $local : $previousLive);
                return 2;
            }
            $paths[] = '/' . ltrim(substr($sentinel, strlen($root)), '/');
        }
        $ok = true;
        try {
            foreach (array_unique($paths) as $path) {
                $response = (new HttpClient())->request('GET', $origin . $path,
                    ['Accept: application/json', 'X-YourShield-Install-Probe: ' . $token], null, 1000, 5000, 4096);
                $data = json_decode((string) ($response['body'] ?? ''), true);
                if ((int) ($response['status'] ?? 0) !== 200 || !is_array($data)
                    || !hash_equals(hash('sha256', $token), (string) ($data['yourshield_probe'] ?? ''))
                ) {
                    $this->log('Hook not yet verified: ' . $path . '. Check server routing and PHP INI propagation.', 'warning');
                    $ok = false;
                }
            }
        } catch (\Throwable) {
            $ok = false;
            $this->log('Hook verification request failed.', 'warning');
        } finally {
            if ($sentinel !== null) {
                @unlink($sentinel);
            }
            unset($local['installation']['probe_hash'], $local['installation']['probe_expires_at']);
        }
        if ($ok) {
            $ok = $this->verifyAssetDelivery($origin, $local);
        }
        $local['enabled'] = $ok;
        $local['installation']['status'] = $ok ? 'active' : 'needs_action';
        $local['installation']['verified_at'] = $ok ? gmdate('c') : null;
        if (!$this->writeLocalConfig(!$ok && ($previousLive['enabled'] ?? false) ? $previousLive : $local)) {
            return 1;
        }
        $this->log($ok ? 'Site connection and configured request hooks verified. Protection enabled.' : 'Additional hosting configuration is required. Protection has not been enabled.');
        return $ok ? 0 : 2;
    }

    private function verifyAssetDelivery(string $origin, array $local): bool
    {
        $assetRoot = rtrim((string) $local['public_root'], '/') . '/' . trim((string) $local['base_path'], '/') . '/a';
        $bundle = AssetUpdater::activeBundleId($assetRoot);
        $manifestPath = $bundle !== null ? $assetRoot . '/' . $bundle . '/.bundle-manifest.json' : '';
        $manifest = is_file($manifestPath) ? json_decode((string) file_get_contents($manifestPath), true) : null;
        $file = is_array($manifest) ? ($manifest['files'][0] ?? null) : null;
        if (!is_array($file) || !is_string($file['name'] ?? null) || !is_string($file['sha256'] ?? null)) {
            $this->log('No verified active challenge bundle is installed.', 'error');
            return false;
        }
        $response = (new HttpClient())->request('GET', $origin . $local['base_path'] . '/a/' . $bundle . '/' . $file['name'], [], null, 1000, 5000);
        $ok = (int) ($response['status'] ?? 0) === 200
            && hash_equals($file['sha256'], hash('sha256', (string) ($response['body'] ?? '')));
        if (!$ok) {
            $this->log('Challenge assets are not served intact from this site.', 'warning');
        }
        return $ok;
    }

    private function withOperationLock(callable $operation): int
    {
        if (!$this->mutationOwnerIsValid()) {
            return 1;
        }
        $path = $this->yourShieldDir . '/.installer-operation.lock';
        clearstatcache(true, $path);
        $before = @lstat($path);
        if (is_array($before) && (($before['mode'] & 0170000) !== 0100000)) {
            $this->log('Installer operation lock must be a regular file.', 'error');
            return 1;
        }
        $handle = @fopen($path, 'c+');
        if (!is_resource($handle)) {
            return 1;
        }
        try {
            clearstatcache(true, $path);
            $opened = fstat($handle);
            $current = @lstat($path);
            if (!is_array($opened) || !is_array($current)
                || ($opened['mode'] & 0170000) !== 0100000 || ($current['mode'] & 0170000) !== 0100000
                || $opened['ino'] !== $current['ino'] || $opened['dev'] !== $current['dev']
                || !flock($handle, LOCK_EX | LOCK_NB)
            ) {
                $this->log('Another installer operation is running. Retry after it finishes.', 'warning');
                return 2;
            }
            @chmod($path, 0600);
            return $operation();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
