<?php
declare(strict_types=1);

$ysPinnedModuleRoot = defined('YS_MODULE_ROOT') && is_string(constant('YS_MODULE_ROOT'))
    ? rtrim((string) constant('YS_MODULE_ROOT'), '/\\')
    : '';
$ysActiveRoot = defined('YS_RELEASE_ROOT') && is_string(constant('YS_RELEASE_ROOT'))
    ? rtrim((string) constant('YS_RELEASE_ROOT'), '/\\')
    : '';
$ysCurrentConfigRoot = str_replace('\\', '/', __DIR__);
$ysIsStableConfig = $ysPinnedModuleRoot !== ''
    && strcasecmp($ysCurrentConfigRoot, str_replace('\\', '/', $ysPinnedModuleRoot)) === 0;
$ysIsReleaseConfig = $ysActiveRoot !== ''
    && strcasecmp($ysCurrentConfigRoot, str_replace('\\', '/', $ysActiveRoot)) === 0;
if ($ysIsStableConfig
    && $ysActiveRoot !== ''
    && strcasecmp(str_replace('\\', '/', $ysActiveRoot), str_replace('\\', '/', __DIR__)) !== 0
    && is_file($ysActiveRoot . '/config.php')
    && !is_link($ysActiveRoot . '/config.php')
) {
    return require $ysActiveRoot . '/config.php';
}

$ysModuleRoot = ($ysIsStableConfig || $ysIsReleaseConfig)
    ? $ysPinnedModuleRoot
    : __DIR__;

$trustedProxyCidrs = array_values(array_filter(array_map(
    'trim',
    explode(',', getenv('YS_TRUSTED_PROXY_CIDRS') ?: '127.0.0.1/32,::1/128')
)));
$cloudAllowedHosts = array_values(array_filter(array_map(
    'trim',
    explode(',', getenv('YS_CLOUD_ALLOWED_HOSTS') ?: '')
)));
$ysProjectRoot = realpath(dirname($ysModuleRoot)) ?: dirname($ysModuleRoot);
$ysRuntimeDirOverride = trim((string) (getenv('YS_RUNTIME_DIR') ?: ''));
$ysCacheDirOverride = trim((string) (getenv('YS_CACHE_DIR') ?: ''));
$ysAutoRuntimeDir = rtrim(sys_get_temp_dir(), '/\\')
    . '/.yourshield-runtime-'
    . substr(hash('sha256', str_replace('\\', '/', $ysProjectRoot)), 0, 16);
$ysRuntimeDir = $ysRuntimeDirOverride !== '' ? rtrim($ysRuntimeDirOverride, '/\\') : $ysAutoRuntimeDir;
$ysCacheDir = $ysCacheDirOverride !== '' ? rtrim($ysCacheDirOverride, '/\\') : $ysRuntimeDir . '/cache';

$config = [
    'enabled' => true,
    'api_ver' => '1',
    'site_key' => getenv('YS_SITE_KEY') ?: 'replace-with-site-key',
    'secret' => getenv('YS_SECRET') ?: 'replace-with-secret',
    'site_host' => getenv('YS_SITE_HOST') ?: '',
    'php_cli' => getenv('YS_PHP_CLI') ?: '',
    'cloud_base_url' => rtrim(getenv('YS_CLOUD_BASE_URL') ?: 'https://cloud.example.com', '/'),
    'trusted_proxy' => [
        'enabled' => filter_var(getenv('YS_TRUSTED_PROXY_ENABLED') ?: '0', FILTER_VALIDATE_BOOLEAN),
        'trusted_cidrs' => $trustedProxyCidrs,
        'ip_header' => getenv('YS_TRUSTED_PROXY_IP_HEADER') ?: 'HTTP_X_FORWARDED_FOR',
        'proto_header' => getenv('YS_TRUSTED_PROXY_PROTO_HEADER') ?: 'HTTP_X_FORWARDED_PROTO',
    ],
    'cloud_url_policy' => [
        'allow_http' => filter_var(getenv('YS_CLOUD_ALLOW_HTTP') ?: '0', FILTER_VALIDATE_BOOLEAN),
        'allow_localhost' => filter_var(getenv('YS_CLOUD_ALLOW_LOCALHOST') ?: '0', FILTER_VALIDATE_BOOLEAN),
        'allow_private_networks' => filter_var(getenv('YS_CLOUD_ALLOW_PRIVATE') ?: '0', FILTER_VALIDATE_BOOLEAN),
        'allowed_hosts' => $cloudAllowedHosts,
    ],
    'bundle_signature' => [
        'mode' => getenv('YS_BUNDLE_SIG_MODE') ?: 'optional', // off|optional|required
        'key' => getenv('YS_BUNDLE_SIG_KEY') ?: '',
        'max_age_sec' => (int) (getenv('YS_BUNDLE_SIG_MAX_AGE_SEC') ?: 1800),
    ],
    'project_root' => $ysProjectRoot,
    'public_root' => getenv('YS_PUBLIC_ROOT') ?: $ysProjectRoot . '/public',
    'base_path' => getenv('YS_BASE_PATH') ?: '/assets/.cache/ys_demo',
    'runtime_dir' => $ysRuntimeDir,
    'runtime_storage_managed' => $ysRuntimeDirOverride === '' && $ysCacheDirOverride === '',
    'cache_dir' => $ysCacheDir,
    'cache' => [
        'driver' => getenv('YS_CACHE_DRIVER') ?: 'auto', // auto|apcu|redis|file
        'prefix' => getenv('YS_CACHE_PREFIX') ?: 'ys:',
        'apcu_prefix' => getenv('YS_APCU_PREFIX') ?: 'ys:',
        'lock_wait_ms' => (int) (getenv('YS_CACHE_LOCK_WAIT_MS') ?: 500),
        'lock_ttl_sec' => (int) (getenv('YS_CACHE_LOCK_TTL_SEC') ?: 5),
        'redis' => [
            'host' => getenv('YS_REDIS_HOST') ?: '127.0.0.1',
            'port' => (int) (getenv('YS_REDIS_PORT') ?: 6379),
            'db' => (int) (getenv('YS_REDIS_DB') ?: 0),
            'password' => getenv('YS_REDIS_PASSWORD') ?: '',
            'timeout_sec' => (float) (getenv('YS_REDIS_TIMEOUT_SEC') ?: 0.2),
            'read_timeout_sec' => (float) (getenv('YS_REDIS_READ_TIMEOUT_SEC') ?: 0.2),
            'prefix' => getenv('YS_REDIS_PREFIX') ?: 'ys:',
        ],
    ],
    'debug' => filter_var(getenv('YS_DEBUG') ?: '0', FILTER_VALIDATE_BOOLEAN),
    'fail_mode' => getenv('YS_FAIL_MODE') ?: 'hybrid', // fail-open|fail-close|hybrid
    'bot_blocking' => [
        'mode' => getenv('YS_BOT_BLOCK_MODE') ?: 'block', // block|whitepage_dir
        'whitepage_dir' => getenv('YS_BOT_WHITEPAGE_DIR') ?: '',
    ],
    'allow_cache_ttl_sec' => (int) (getenv('YS_ALLOW_TTL_SEC') ?: 900),
    'browser_proof' => [
        'enabled' => filter_var(getenv('YS_BROWSER_PROOF_ENABLED') !== false ? getenv('YS_BROWSER_PROOF_ENABLED') : '1', FILTER_VALIDATE_BOOLEAN),
    ],
    'rid_ttl_sec' => (int) (getenv('YS_RID_TTL_SEC') ?: 180),
    'rid_max_tries' => (int) (getenv('YS_RID_MAX_TRIES') ?: 5),
    'body_limit_bytes' => (int) (getenv('YS_BODY_LIMIT_BYTES') ?: 32768),
    'timeouts' => [
        'connect_ms' => (int) (getenv('YS_CONNECT_TIMEOUT_MS') ?: 500),
        'total_ms' => (int) (getenv('YS_TOTAL_TIMEOUT_MS') ?: 2000),
    ],
    'metrics_flush_interval_sec' => (int) (getenv('YS_METRICS_FLUSH_INTERVAL_SEC') ?: 60),
    'metrics' => [
        'flush_interval_sec' => (int) (getenv('YS_METRICS_FLUSH_INTERVAL_SEC') ?: 60),
        'flush_lock_ttl_sec' => (int) (getenv('YS_METRICS_FLUSH_LOCK_TTL_SEC') ?: 10),
        'flush_backoff_base_sec' => (int) (getenv('YS_METRICS_BACKOFF_BASE_SEC') ?: 5),
        'flush_backoff_max_sec' => (int) (getenv('YS_METRICS_BACKOFF_MAX_SEC') ?: 60),
    ],
    'web_installer' => [
        'enabled' => filter_var(getenv('YS_WEB_INSTALLER_ENABLED') ?: '0', FILTER_VALIDATE_BOOLEAN),
        'token' => getenv('YS_WEB_INSTALLER_TOKEN') ?: '',
        'allow_local_without_token' => false,
    ],
    'assets' => [
        'updater_lock_wait_ms' => (int) (getenv('YS_ASSETS_LOCK_WAIT_MS') ?: 5000),
        'updater_lock_ttl_sec' => (int) (getenv('YS_ASSETS_LOCK_TTL_SEC') ?: 120),
        'keep_generations' => (int) (getenv('YS_ASSETS_KEEP_GENERATIONS') ?: 2),
        'verify_sha256' => filter_var(getenv('YS_ASSETS_VERIFY_SHA256') ?: '1', FILTER_VALIDATE_BOOLEAN),
        'auto_update' => [
            'enabled' => filter_var(getenv('YS_ASSETS_AUTO_UPDATE') ?: '1', FILTER_VALIDATE_BOOLEAN),
            'interval_sec' => (int) (getenv('YS_ASSETS_AUTO_UPDATE_INTERVAL_SEC') ?: 900),
            'on_html_only' => filter_var(getenv('YS_ASSETS_AUTO_UPDATE_HTML_ONLY') ?: '1', FILTER_VALIDATE_BOOLEAN),
            'lock_ttl_sec' => (int) (getenv('YS_ASSETS_AUTO_UPDATE_LOCK_TTL_SEC') ?: 6),
        ],
    ],
    'module_version' => getenv('YS_MODULE_VERSION') ?: (
        is_file(__DIR__ . '/version.txt') ? trim((string) file_get_contents(__DIR__ . '/version.txt')) : '1.1.4'
    ),
    'module_update' => [
        'enabled' => filter_var(getenv('YS_MODULE_AUTO_UPDATE') ?: '1', FILTER_VALIDATE_BOOLEAN),
        'interval_sec' => (int) (getenv('YS_MODULE_AUTO_UPDATE_INTERVAL_SEC') ?: 21600),
        'on_html_only' => filter_var(getenv('YS_MODULE_AUTO_UPDATE_HTML_ONLY') ?: '1', FILTER_VALIDATE_BOOLEAN),
        'lock_ttl_sec' => (int) (getenv('YS_MODULE_AUTO_UPDATE_LOCK_TTL_SEC') ?: 6),
        'channel' => getenv('YS_MODULE_UPDATE_CHANNEL') ?: 'stable',
        'verify_sha256' => filter_var(getenv('YS_MODULE_UPDATE_VERIFY_SHA256') ?: '1', FILTER_VALIDATE_BOOLEAN),
        'lock_wait_ms' => (int) (getenv('YS_MODULE_UPDATE_LOCK_WAIT_MS') ?: 3000),
        'backup_keep' => (int) (getenv('YS_MODULE_UPDATE_BACKUP_KEEP') ?: 2),
    ],
    'strict_path_prefixes' => [
        '/admin',
        '/login',
        '/signin',
        '/wp-login.php',
    ],
    'excluded_path_prefixes' => [
        '/favicon.ico',
        '/robots.txt',
    ],
    'rate_limits' => [
        'base' => ['rate_per_sec' => 2.0, 'burst' => 120],
        'check' => ['rate_per_sec' => 1.0, 'burst' => 60],
        'challenge' => ['rate_per_sec' => 0.33, 'burst' => 20],
        'solve' => ['rate_per_sec' => 0.5, 'burst' => 30],
        'ingest' => ['rate_per_sec' => 1.0, 'burst' => 60],
    ],
    'route_bundle' => [
        'current' => [
            'id' => 'bootstrap',
            'challenge_path' => '/c/bootstrap',
            'solve_path' => '/s/bootstrap',
            'session_ingest_path' => '/e/bootstrap',
            'metrics_ingest_path' => '/m/bootstrap',
        ],
        'prev' => null,
    ],
    'route_bundle_policy' => [
        'default_ttl_sec' => (int) (getenv('YS_ROUTE_TTL_DEFAULT_SEC') ?: 900),
        'prev_grace_sec' => (int) (getenv('YS_ROUTE_PREV_GRACE_SEC') ?: 600),
        'persist_ttl_sec' => (int) (getenv('YS_ROUTE_PERSIST_TTL_SEC') ?: 86400),
    ],
    'loop_protection' => [
        'enabled' => filter_var(getenv('YS_LOOP_ENABLED') ?: '1', FILTER_VALIDATE_BOOLEAN),
        'ttl_sec' => (int) (getenv('YS_LOOP_TTL_SEC') ?: 120),
        'max_challenges' => (int) (getenv('YS_LOOP_MAX_CHALLENGES') ?: 5),
        'action' => getenv('YS_LOOP_ACTION') ?: 'block', // fail_mode|block|allow
    ],
    'cloud_paths' => [
        'site_handshake' => '/v1/site/handshake',
        'check' => '/v1/check',
        'challenge_html' => '/v1/challenge/html',
        'challenge_solve' => '/v1/challenge/solve',
        'metrics_ingest' => '/v1/metrics/ingest',
        'session_ingest' => '/v1/session/ingest',
        'assets_manifest' => '/v1/assets/manifest',
        'assets_bundle' => '/v1/assets/bundle',
        'module_manifest' => '/v1/module/manifest',
        'module_file' => '/v1/module/file',
    ],
];

$localPath = $ysModuleRoot . '/config.local.php';
if (is_file($localPath)) {
    $local = require $localPath;
    if (is_array($local)) {
        $config = array_replace_recursive($config, $local);
    }
}

return $config;
