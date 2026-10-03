<?php
declare(strict_types=1);

use YourShield\Installer;
use YourShield\RuntimeConfig;
use YourShield\SetupAccess;
use YourShield\Utils;

// Entry wrappers pin the immutable release before this file is loaded.
if (!defined('YS_MODULE_ROOT') || !defined('YS_RELEASE_ROOT')) {
    http_response_code(404);
    exit;
}
$moduleRoot = rtrim((string) constant('YS_MODULE_ROOT'), '/\\');
$projectRoot = dirname($moduleRoot);
$configPath = rtrim((string) constant('YS_RELEASE_ROOT'), '/\\') . '/config.php';
$runtime = RuntimeConfig::fromFile($configPath);
$webCfg = $runtime->getArray('web_installer');
$enabled = (bool) ($webCfg['enabled'] ?? false);
$trustedProxyCfg = $runtime->getArray('trusted_proxy');
$expectedToken = trim((string) ($webCfg['token'] ?? ''));
$secureRequest = Utils::requestScheme($_SERVER, $trustedProxyCfg) === 'https';

session_name('ys_installer');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_set_cookie_params(['httponly' => true, 'secure' => $secureRequest, 'samesite' => 'Strict', 'path' => '/']);
session_start();
$nonce = base64_encode(random_bytes(18));
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: private, no-store');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-" . $nonce . "'; style-src 'nonce-" . $nonce . "'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");

$requestPath = parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
if (!is_string($requestPath) || !str_starts_with($requestPath, '/') || str_starts_with($requestPath, '//')
    || preg_match('/[\\\\\x00-\x20\x7f]/', $requestPath)) {
    $requestPath = '/ys-install.php';
}
$redirect = static function (array $params = []) use ($requestPath): void {
    header('Location: ' . $requestPath . ($params === [] ? '' : '?' . http_build_query($params)), true, 303);
    exit;
};
$configuredTokenHash = $expectedToken !== '' ? hash('sha256', $expectedToken) : '';
if (array_key_exists('token', $_GET)) {
    $queryToken = is_string($_GET['token']) ? trim($_GET['token']) : '';
    if ($enabled && $expectedToken !== '' && hash_equals($expectedToken, $queryToken)) {
        session_regenerate_id(true);
        $_SESSION['ys_installer_token_hash'] = $configuredTokenHash;
    } else {
        unset($_SESSION['ys_installer_token_hash'], $_SESSION['ys_installer_draft'], $_SESSION['ys_installer_result']);
    }
    $params = $_GET;
    unset($params['token']);
    $redirect($params);
}
$sessionTokenHash = is_string($_SESSION['ys_installer_token_hash'] ?? null) ? $_SESSION['ys_installer_token_hash'] : '';
$isAuthorized = $enabled && $expectedToken !== '' && $sessionTokenHash !== '' && hash_equals($configuredTokenHash, $sessionTokenHash);
$setupAccess = new SetupAccess($runtime);
$setupAvailable = $setupAccess->available();
$setupCompleted = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && !empty($_SESSION['ys_setup_finished']);
unset($_SESSION['ys_setup_finished']);
if (!is_string($_SESSION['ys_csrf'] ?? null) || $_SESSION['ys_csrf'] === '') {
    $_SESSION['ys_csrf'] = bin2hex(random_bytes(24));
}
$csrf = $_SESSION['ys_csrf'];
$postText = static fn (string $key, string $fallback = ''): string => is_string($_POST[$key] ?? null) ? trim($_POST[$key]) : $fallback;
$setupError = is_string($_SESSION['ys_setup_error'] ?? null) ? $_SESSION['ys_setup_error'] : '';
unset($_SESSION['ys_setup_error']);
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && $postText('action') === 'authorize') {
    try {
        if (!hash_equals($csrf, $postText('csrf'))) { throw new DomainException('setup_access_denied'); }
        $setupAccess->authorize($postText('setup_code'), (string) ($_SERVER['HTTP_HOST'] ?? ''));
    } catch (Throwable $exception) { $_SESSION['ys_setup_error'] = 'setup_access_denied'; }
    $redirect(['lang' => in_array($postText('ui_lang'), ['ru', 'en'], true) ? $postText('ui_lang') : 'en']);
}
$isAuthorized = $isAuthorized || $setupAccess->isAuthorized();
if (!$isAuthorized && !$setupCompleted) {
    unset($_SESSION['ys_installer_token_hash'], $_SESSION['ys_installer_draft'], $_SESSION['ys_installer_result']);
}
$setupCredentials = $setupAccess->pendingCredentials();
$setupCredentialsReady = $setupCredentials !== [];
$langInput = $postText('ui_lang', is_string($_GET['lang'] ?? null) ? $_GET['lang'] : '');
$cookieLang = is_string($_COOKIE['ys_installer_lang'] ?? null) ? $_COOKIE['ys_installer_lang'] : '';
$uiLang = in_array($langInput, ['ru', 'en'], true) ? $langInput : (in_array($cookieLang, ['ru', 'en'], true) ? $cookieLang : 'en');
if ($langInput === '' && $cookieLang === '') {
    foreach (explode(',', strtolower((string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''))) as $language) {
        $primary = substr(trim($language), 0, 2);
        if (in_array($primary, ['ru', 'en'], true)) { $uiLang = $primary; break; }
    }
}
setcookie('ys_installer_lang', $uiLang, ['expires' => time() + 31536000, 'path' => '/', 'secure' => $secureRequest, 'samesite' => 'Lax']);
$translations = [
    'en' => [
        'page_title' => 'Connect your site · YourShield',
        'subtitle' => 'SITE PROTECTION',
        'lang_label' => 'Language',
        'theme_label' => 'Theme',
        'theme_auto' => 'Auto',
        'theme_light' => 'Light',
        'theme_dark' => 'Dark',
        'installer_disabled' => 'Web installer is disabled.',
        'unauthorized' => 'Unauthorized. Open this page once with a valid `?token=...`.',
        'exit_code' => 'Exit Code',
        'csrf_failed' => 'CSRF check failed',
        'unknown_action' => 'Unknown action',
        'preflight_title' => 'Preflight Checks',
        'state_ok' => 'OK',
        'state_fail' => 'FAIL',
        'label_site_key' => 'Site key',
        'desc_site_key' => 'Public identifier issued by your control panel/cloud.',
        'label_site_host' => 'Website hostname',
        'desc_site_host' => 'The domain name visitors use to open this site.',
        'placeholder_site_host' => 'example.com',
        'label_secret' => 'Site secret',
        'desc_secret' => 'Private connection key. Leave blank to keep the saved key.',
        'label_cloud_url' => 'TDS cloud address',
        'desc_cloud_url' => 'HTTPS origin of the YourShield cloud API.',
        'placeholder_cloud_url' => 'https://cloud.example.com',
        'label_base_path' => 'Protection route prefix',
        'desc_base_path' => 'Internal protected path prefix for challenge/assets routes.',
        'placeholder_base_path' => '/assets/.cache/abc123xyz789',
        'label_bot_block_mode' => 'When a visitor is blocked',
        'desc_bot_block_mode' => 'Choose whether blocked bots see deny page or local whitepage.',
        'bot_mode_block' => 'Show an access denied page',
        'bot_mode_whitepage_dir' => 'Show a local alternative page',
        'label_bot_whitepage_dir' => 'Bot Whitepage Directory',
        'desc_bot_whitepage_dir' => 'Directory inside public root with whitepage HTML files.',
        'placeholder_bot_whitepage_dir' => '/whitepages',
        'button_install' => 'Connect protection',
        'advanced_settings' => 'Advanced Settings',
        'label_probe_url' => 'Probe URL (Optional)',
        'desc_probe_url' => 'Origin used by installer Test to verify health/challenge endpoints.',
        'placeholder_probe_url' => 'https://example.com',
        'label_assets_auto_update_enabled' => 'Update verification files automatically',
        'desc_assets_auto_update_enabled' => 'Background updates require permission to run PHP CLI. Otherwise use authenticated web maintenance.',
        'cron_hint_disabled' => 'Lazy auto-update is disabled. Add cron jobs:',
        'label_assets_auto_update_interval_sec' => 'Assets Auto-Update Interval (Sec)',
        'desc_assets_auto_update_interval_sec' => 'Minimum delay between automatic asset refreshes.',
        'placeholder_assets_auto_update_interval_sec' => '900',
        'label_module_auto_update_enabled' => 'Update the protection module automatically',
        'desc_module_auto_update_enabled' => 'Background updates require permission to run PHP CLI. Otherwise use authenticated web maintenance.',
        'label_module_auto_update_interval_sec' => 'Module Auto-Update Interval (Sec)',
        'desc_module_auto_update_interval_sec' => 'Minimum delay between automatic module updates.',
        'placeholder_module_auto_update_interval_sec' => '21600',
        'label_trusted_proxy_provider' => 'Trusted Proxy CDN',
        'desc_trusted_proxy_provider' => 'Provider used to auto-fetch trusted edge IP ranges.',
        'label_trusted_proxy_enabled' => 'Enable Trusted Proxy Mode',
        'desc_trusted_proxy_enabled' => 'Trust `X-Forwarded-*` only from configured CIDRs.',
        'label_trusted_proxy_auto_ips' => 'Auto-load CDN IP ranges',
        'desc_trusted_proxy_auto_ips' => 'Download and merge provider CIDRs automatically.',
        'label_trusted_proxy_cidrs' => 'Trusted CIDRs (extra, comma/newline)',
        'desc_trusted_proxy_cidrs' => 'Additional CIDRs to trust on top of provider ranges.',
        'placeholder_trusted_proxy_cidrs' => '203.0.113.0/24, 2001:db8::/32',
        'label_trusted_proxy_ip_header' => 'Client IP header',
        'desc_trusted_proxy_ip_header' => 'HTTP header containing original client IP.',
        'placeholder_trusted_proxy_ip_header' => 'HTTP_X_FORWARDED_FOR',
        'label_trusted_proxy_proto_header' => 'Proto header',
        'desc_trusted_proxy_proto_header' => 'HTTP header containing original request scheme.',
        'placeholder_trusted_proxy_proto_header' => 'HTTP_X_FORWARDED_PROTO',
        'label_entrypoints' => 'Entrypoints (Comma Separated, Optional)',
        'desc_entrypoints' => 'PHP front controllers that should include YourShield bootstrap.',
        'placeholder_entrypoints' => 'public/index.php,index.php',
        'label_cms' => 'CMS Profile',
        'desc_cms' => 'Detected profile affects default excludes/strict path presets.',
        'label_use_cms_presets' => 'Apply CMS presets (excluded/strict paths)',
        'desc_use_cms_presets' => 'Recommended for common CMS setups.',
        'label_runtime_env' => 'Runtime Environment',
        'desc_runtime_env' => 'Use `auto` unless webserver detection is unavailable.',
        'label_runtime_dir' => 'Shared Runtime Directory',
        'desc_runtime_dir' => 'Absolute private path shared by PHP-FPM and cron; do not use /tmp with systemd PrivateTmp.',
        'placeholder_runtime_dir' => '/var/lib/yourshield/example.com',
        'label_cache_dir' => 'Shared Cache Directory',
        'desc_cache_dir' => 'Absolute private cache path outside the public root.',
        'placeholder_cache_dir' => '/var/lib/yourshield/example.com/cache',
        'label_cache_driver' => 'Cache Driver',
        'desc_cache_driver' => 'Select backend used for runtime cache storage.',
        'cache_driver_auto' => 'Auto (APCu -> Redis -> File)',
        'label_cache_prefix' => 'Cache Prefix',
        'desc_cache_prefix' => 'Prefix for all cache keys (APCu/Redis namespaces).',
        'placeholder_cache_prefix' => 'ys:',
        'label_cache_apcu_prefix' => 'APCu Prefix',
        'desc_cache_apcu_prefix' => 'Dedicated prefix for APCu driver (optional).',
        'placeholder_cache_apcu_prefix' => 'ys:',
        'label_cache_lock_wait_ms' => 'Lock Wait (Ms)',
        'desc_cache_lock_wait_ms' => 'Maximum wait time to acquire cache mutation lock.',
        'placeholder_cache_lock_wait_ms' => '500',
        'label_cache_lock_ttl_sec' => 'Lock TTL (Sec)',
        'desc_cache_lock_ttl_sec' => 'TTL for cache mutation lock keys.',
        'placeholder_cache_lock_ttl_sec' => '5',
        'label_cache_redis_host' => 'Redis Host',
        'desc_cache_redis_host' => 'Hostname or IP of Redis server.',
        'placeholder_cache_redis_host' => '127.0.0.1',
        'label_cache_redis_port' => 'Redis Port',
        'desc_cache_redis_port' => 'TCP port for Redis connection.',
        'placeholder_cache_redis_port' => '6379',
        'label_cache_redis_db' => 'Redis DB',
        'desc_cache_redis_db' => 'Redis database index (>= 0).',
        'placeholder_cache_redis_db' => '0',
        'label_cache_redis_password' => 'Redis Password',
        'desc_cache_redis_password' => 'Password for Redis AUTH. Leave blank to keep the saved value.',
        'placeholder_cache_redis_password' => 'optional',
        'label_cache_redis_timeout_sec' => 'Redis Connect Timeout (Sec)',
        'desc_cache_redis_timeout_sec' => 'Connect timeout for Redis backend.',
        'placeholder_cache_redis_timeout_sec' => '0.2',
        'label_cache_redis_read_timeout_sec' => 'Redis Read Timeout (Sec)',
        'desc_cache_redis_read_timeout_sec' => 'Socket read timeout for Redis backend.',
        'placeholder_cache_redis_read_timeout_sec' => '0.2',
        'label_cache_redis_prefix' => 'Redis Prefix',
        'desc_cache_redis_prefix' => 'Prefix for Redis keys (defaults to cache prefix).',
        'placeholder_cache_redis_prefix' => 'ys:',
        'button_test' => 'Test',
        'button_update_assets' => 'Update Assets',
        'button_update_module' => 'Update Module',
        'manual_routing_hints' => 'Manual Routing Hints',
        'logs_title' => 'Logs',
        'option_auto' => 'Auto',
        'step_connect' => 'Connection',
        'step_review' => 'Review',
        'step_done' => 'Result',
        'intro_title' => 'Protection starts here.',
        'intro_body' => 'Connect this site to YourShield. Your content and website address stay the same.',
        'connection_hint' => 'Copy the connection details from Sites in your KEHR panel.',
        'next' => 'Continue',
        'back' => 'Back',
        'review_title' => 'Review your setup',
        'review_body' => 'Check the website and connect protection. The installer will show instructions if your hosting needs extra configuration.',
        'runtime_php_builtin' => 'PHP development server',
        'runtime_unknown' => 'Server not detected',
        'environment' => 'Your website',
        'detected' => 'Detected environment',
        'default_settings' => 'Connection settings',
        'advanced_hint' => 'Hosting, proxy, cache and protection options',
        'group_connection' => 'Website integration',
        'group_protection' => 'Protection',
        'group_proxy' => 'Proxy / CDN',
        'group_updates' => 'Updates',
        'group_storage' => 'Cache and storage',
        'details' => 'Technical details',
        'maintenance' => 'Maintenance',
        'maintenance_hint' => 'Changes to an existing installation require a separate action.',
        'button_disable' => 'Turn off protection',
        'button_rollback' => 'Restore previous version',
        'button_uninstall' => 'Remove connection',
        'confirm_uninstall' => 'I understand that this removes the YourShield connection and stops protection.',
        'confirm_disable' => 'I understand that visitors will no longer be checked by YourShield.',
        'confirm_rollback' => 'I want to activate the previously installed module version.',
        'uninstall_title' => 'Remove the connection',
        'disable_title' => 'Turn off protection',
        'rollback_title' => 'Restore the previous version',
        'confirm_required' => 'Confirm this action before continuing.',
        'errors_title' => 'Check the highlighted fields',
        'field_required' => 'Enter this value.',
        'field_invalid' => 'Check the value and try again.',
        'cloud_invalid' => 'Enter the permitted HTTPS cloud address from KEHR.',
        'secret_again' => 'For your security, enter the secret again. It was not saved in this form.',
        'operation_failed' => 'The operation could not be completed. Review the details below and try again.',
        'needs_action' => 'One more step on your hosting',
        'needs_action_body' => 'Files are prepared. Apply the connection instructions, then check again. Protection is not active yet.',
        'installed_title' => 'Protection is connected',
        'installed_body' => 'The selected integration passed its checks. Review its coverage and open your site.',
        'operation_done' => 'Action completed',
        'operation_done_body' => 'The requested operation completed. Its checks are listed below.',
        'not_verified' => 'Connection saved — verification required',
        'not_verified_body' => 'File setup alone does not prove that visitor protection is running. Check the connection on your hosting.',
        'button_verify' => 'Check connection again',
        'open_site' => 'Open site',
        'edit_settings' => 'Change settings',
        'coverage' => 'Protection coverage',
        'not_active' => 'Not yet verified',
        'active' => 'Active',
        'locked_title' => 'This installer is locked',
        'locked_body' => 'Use the personal setup package or installer access issued by your site administrator.',
        'locked_footer' => 'Access is required before website settings can be viewed or changed.',
        'label_setup_code' => 'Setup code',
        'desc_setup_code' => 'Use the code shown in Sites in your KEHR panel.',
        'button_authorize' => 'Unlock setup',
        'setup_error' => 'The setup code could not be accepted. Check the code or request a new package.',
        'setup_ready' => 'Your connection details are ready',
        'setup_ready_hint' => 'They were received securely for this installation.',
        'label_document_root' => 'Public website directory',
        'desc_document_root' => 'The directory actually served by the web server. Leave empty for detection.',
        'label_mount_path' => 'Website URL prefix',
        'desc_mount_path' => 'Leave empty for the domain root, or enter a prefix such as /shop.',
        'label_integration_method' => 'Connection method',
        'desc_integration_method' => 'Auto selects a method supported by this hosting. Review the detected coverage.',
        'integration_auto' => 'Automatic',
        'integration_prepend' => 'Before every PHP request',
        'integration_entrypoint' => 'Selected PHP entrypoints',
        'integration_static' => 'Static HTML gateway',
        'integration_manual' => 'Manual integration',
        'label_browser_proof_enabled' => 'Remember browser verification',
        'desc_browser_proof_enabled' => 'Use a secure first-party cookie. Website policy is still checked for each protected request.',
        'busy' => 'Checking…',
        'update_pending' => 'The update is being prepared',
        'update_pending_body' => 'The current version is still active. Continue to check the remaining files and finish the update.',
        'continue_update' => 'Continue update',
        'connection_metadata' => 'Connection details',
        'setup_closed' => 'Setup is closed. Future changes require fresh access.',
        'reconfigure_warning' => 'These changes apply to the existing connection. The previous configuration is restored if installation fails.',
        'check_not_run' => 'Check not run',
        'check_unavailable' => 'Environment checks are unavailable. Open technical details.',
        'required_mark' => 'Required',
        'optional_mark' => 'Optional',
        'no_js' => 'All settings and actions remain available without JavaScript.',
    ],
    'ru' => [
        'page_title' => 'Подключение сайта · YourShield',
        'subtitle' => 'ЗАЩИТА САЙТА',
        'lang_label' => 'Язык',
        'theme_label' => 'Тема',
        'theme_auto' => 'Авто',
        'theme_light' => 'Светлая',
        'theme_dark' => 'Темная',
        'installer_disabled' => 'Веб-установщик отключен.',
        'unauthorized' => 'Нет доступа. Один раз откройте страницу с корректным `?token=...`.',
        'exit_code' => 'код выхода',
        'csrf_failed' => 'Ошибка проверки CSRF',
        'unknown_action' => 'Неизвестное действие',
        'preflight_title' => 'Проверки Перед Установкой',
        'state_ok' => 'OK',
        'state_fail' => 'FAIL',
        'label_site_key' => 'Ключ сайта',
        'desc_site_key' => 'Публичный идентификатор сайта из панели управления/облака.',
        'label_site_host' => 'Домен сайта',
        'desc_site_host' => 'Домен, по которому посетители открывают этот сайт.',
        'placeholder_site_host' => 'example.com',
        'label_secret' => 'Секрет сайта',
        'desc_secret' => 'Приватный ключ подключения. Оставьте пустым, чтобы сохранить текущий ключ.',
        'label_cloud_url' => 'Адрес облака TDS',
        'desc_cloud_url' => 'HTTPS origin облачного API YourShield.',
        'placeholder_cloud_url' => 'https://cloud.example.com',
        'label_base_path' => 'Префикс маршрутов защиты',
        'desc_base_path' => 'Внутренний префикс путей для challenge/assets маршрутов.',
        'placeholder_base_path' => '/assets/.cache/abc123xyz789',
        'label_bot_block_mode' => 'При блокировке посетителя',
        'desc_bot_block_mode' => 'Что показывать заблокированным ботам: deny page или локальный whitepage.',
        'bot_mode_block' => 'Показать страницу отказа',
        'bot_mode_whitepage_dir' => 'Показать другую локальную страницу',
        'label_bot_whitepage_dir' => 'Директория Bot Whitepage',
        'desc_bot_whitepage_dir' => 'Директория в public root с HTML-файлами whitepage.',
        'placeholder_bot_whitepage_dir' => '/whitepages',
        'button_install' => 'Подключить защиту',
        'advanced_settings' => 'Расширенные настройки',
        'label_probe_url' => 'Probe URL (опционально)',
        'desc_probe_url' => 'Origin, который используется в Test для проверки health/challenge эндпоинтов.',
        'placeholder_probe_url' => 'https://example.com',
        'label_assets_auto_update_enabled' => 'Автоматически обновлять файлы проверки',
        'desc_assets_auto_update_enabled' => 'Для фоновых обновлений нужен разрешённый запуск PHP CLI. Иначе используйте веб-обслуживание с ключом администратора.',
        'cron_hint_disabled' => 'Ленивое автообновление выключено. Добавьте задачи в cron:',
        'label_assets_auto_update_interval_sec' => 'Интервал автообновления assets (сек)',
        'desc_assets_auto_update_interval_sec' => 'Минимальная пауза между автообновлениями ассетов.',
        'placeholder_assets_auto_update_interval_sec' => '900',
        'label_module_auto_update_enabled' => 'Автоматически обновлять модуль защиты',
        'desc_module_auto_update_enabled' => 'Для фоновых обновлений нужен разрешённый запуск PHP CLI. Иначе используйте веб-обслуживание с ключом администратора.',
        'label_module_auto_update_interval_sec' => 'Интервал автообновления модуля (сек)',
        'desc_module_auto_update_interval_sec' => 'Минимальная пауза между автообновлениями модуля.',
        'placeholder_module_auto_update_interval_sec' => '21600',
        'label_trusted_proxy_provider' => 'Провайдер trusted proxy',
        'desc_trusted_proxy_provider' => 'Провайдер для автозагрузки доверенных edge CIDR.',
        'label_trusted_proxy_enabled' => 'Включить режим trusted proxy',
        'desc_trusted_proxy_enabled' => 'Доверять `X-Forwarded-*` только из указанных CIDR.',
        'label_trusted_proxy_auto_ips' => 'Автозагрузка CDN IP ranges',
        'desc_trusted_proxy_auto_ips' => 'Скачивать и объединять CIDR провайдера автоматически.',
        'label_trusted_proxy_cidrs' => 'Trusted CIDRs (доп., через запятую/новую строку)',
        'desc_trusted_proxy_cidrs' => 'Дополнительные CIDR сверх диапазонов провайдера.',
        'placeholder_trusted_proxy_cidrs' => '203.0.113.0/24, 2001:db8::/32',
        'label_trusted_proxy_ip_header' => 'Заголовок IP клиента',
        'desc_trusted_proxy_ip_header' => 'HTTP-заголовок с исходным IP клиента.',
        'placeholder_trusted_proxy_ip_header' => 'HTTP_X_FORWARDED_FOR',
        'label_trusted_proxy_proto_header' => 'Заголовок протокола',
        'desc_trusted_proxy_proto_header' => 'HTTP-заголовок с исходной схемой запроса.',
        'placeholder_trusted_proxy_proto_header' => 'HTTP_X_FORWARDED_PROTO',
        'label_entrypoints' => 'Entrypoints (через запятую, опционально)',
        'desc_entrypoints' => 'PHP front-controller файлы, куда добавить bootstrap YourShield.',
        'placeholder_entrypoints' => 'public/index.php,index.php',
        'label_cms' => 'Профиль CMS',
        'desc_cms' => 'Определенный профиль влияет на пресеты исключений и strict путей.',
        'label_use_cms_presets' => 'Применить CMS пресеты (excluded/strict paths)',
        'desc_use_cms_presets' => 'Рекомендуется для типовых CMS-конфигураций.',
        'label_runtime_env' => 'Окружение runtime',
        'desc_runtime_env' => 'Используйте `auto`, если нет проблем с определением веб-сервера.',
        'label_runtime_dir' => 'Общая Runtime Директория',
        'desc_runtime_dir' => 'Абсолютный приватный путь, общий для PHP-FPM и cron; не используйте /tmp при systemd PrivateTmp.',
        'placeholder_runtime_dir' => '/var/lib/yourshield/example.com',
        'label_cache_dir' => 'Общая Cache Директория',
        'desc_cache_dir' => 'Абсолютный приватный путь кеша вне public root.',
        'placeholder_cache_dir' => '/var/lib/yourshield/example.com/cache',
        'label_cache_driver' => 'Драйвер Кеша',
        'desc_cache_driver' => 'Выберите backend для хранения runtime-кеша.',
        'cache_driver_auto' => 'Auto (APCu -> Redis -> File)',
        'label_cache_prefix' => 'Префикс Кеша',
        'desc_cache_prefix' => 'Префикс ключей кеша (namespace для APCu/Redis).',
        'placeholder_cache_prefix' => 'ys:',
        'label_cache_apcu_prefix' => 'Префикс APCu',
        'desc_cache_apcu_prefix' => 'Отдельный префикс для APCu-драйвера (опционально).',
        'placeholder_cache_apcu_prefix' => 'ys:',
        'label_cache_lock_wait_ms' => 'Ожидание Лока (мс)',
        'desc_cache_lock_wait_ms' => 'Максимальное ожидание блокировки при изменении кеша.',
        'placeholder_cache_lock_wait_ms' => '500',
        'label_cache_lock_ttl_sec' => 'TTL Лока (сек)',
        'desc_cache_lock_ttl_sec' => 'TTL ключей блокировки изменения кеша.',
        'placeholder_cache_lock_ttl_sec' => '5',
        'label_cache_redis_host' => 'Redis Host',
        'desc_cache_redis_host' => 'Хост или IP Redis-сервера.',
        'placeholder_cache_redis_host' => '127.0.0.1',
        'label_cache_redis_port' => 'Redis Port',
        'desc_cache_redis_port' => 'TCP-порт подключения к Redis.',
        'placeholder_cache_redis_port' => '6379',
        'label_cache_redis_db' => 'Redis DB',
        'desc_cache_redis_db' => 'Индекс базы Redis (>= 0).',
        'placeholder_cache_redis_db' => '0',
        'label_cache_redis_password' => 'Redis Password',
        'desc_cache_redis_password' => 'Пароль для AUTH в Redis. Оставьте пустым, чтобы сохранить текущее значение.',
        'placeholder_cache_redis_password' => 'опционально',
        'label_cache_redis_timeout_sec' => 'Таймаут Подключения Redis (сек)',
        'desc_cache_redis_timeout_sec' => 'Таймаут соединения с Redis backend.',
        'placeholder_cache_redis_timeout_sec' => '0.2',
        'label_cache_redis_read_timeout_sec' => 'Таймаут Чтения Redis (сек)',
        'desc_cache_redis_read_timeout_sec' => 'Таймаут чтения сокета Redis backend.',
        'placeholder_cache_redis_read_timeout_sec' => '0.2',
        'label_cache_redis_prefix' => 'Префикс Redis',
        'desc_cache_redis_prefix' => 'Префикс ключей Redis (по умолчанию равен cache prefix).',
        'placeholder_cache_redis_prefix' => 'ys:',
        'button_test' => 'Проверить',
        'button_update_assets' => 'Обновить Assets',
        'button_update_module' => 'Обновить Модуль',
        'manual_routing_hints' => 'Подсказки для ручной маршрутизации',
        'logs_title' => 'Логи',
        'option_auto' => 'Авто',
        'step_connect' => 'Подключение',
        'step_review' => 'Проверка',
        'step_done' => 'Результат',
        'intro_title' => 'Начните с подключения.',
        'intro_body' => 'Подключите сайт к YourShield. Его содержимое и адрес останутся прежними.',
        'connection_hint' => 'Скопируйте данные подключения из раздела «Сайты» в панели KEHR.',
        'next' => 'Продолжить',
        'back' => 'Назад',
        'review_title' => 'Проверка настроек',
        'review_body' => 'Проверьте сайт и подключите защиту. Если потребуется настройка хостинга, мастер покажет инструкции.',
        'runtime_php_builtin' => 'Встроенный PHP-сервер',
        'runtime_unknown' => 'Сервер не определён',
        'environment' => 'Ваш сайт',
        'detected' => 'Найденное окружение',
        'default_settings' => 'Настройки подключения',
        'advanced_hint' => 'Хостинг, прокси, кэш и параметры защиты',
        'group_connection' => 'Подключение к сайту',
        'group_protection' => 'Защита',
        'group_proxy' => 'Прокси / CDN',
        'group_updates' => 'Обновления',
        'group_storage' => 'Кэш и хранение',
        'details' => 'Технические подробности',
        'maintenance' => 'Обслуживание',
        'maintenance_hint' => 'Действия с существующей установкой выполняются отдельно.',
        'button_disable' => 'Отключить защиту',
        'button_rollback' => 'Вернуть предыдущую версию',
        'button_uninstall' => 'Удалить подключение',
        'confirm_uninstall' => 'Я понимаю, что подключение YourShield будет удалено и защита прекратится.',
        'confirm_disable' => 'Я понимаю, что YourShield перестанет проверять посетителей.',
        'confirm_rollback' => 'Я хочу включить ранее установленную версию модуля.',
        'uninstall_title' => 'Удаление подключения',
        'disable_title' => 'Отключение защиты',
        'rollback_title' => 'Возврат предыдущей версии',
        'confirm_required' => 'Подтвердите действие, чтобы продолжить.',
        'errors_title' => 'Проверьте отмеченные поля',
        'field_required' => 'Заполните это поле.',
        'field_invalid' => 'Проверьте значение и повторите попытку.',
        'cloud_invalid' => 'Введите разрешённый HTTPS-адрес облака из KEHR.',
        'secret_again' => 'Для безопасности введите секрет ещё раз. Он не сохраняется в этой форме.',
        'operation_failed' => 'Не удалось завершить действие. Посмотрите подробности ниже и повторите попытку.',
        'needs_action' => 'Остался шаг на хостинге',
        'needs_action_body' => 'Файлы подготовлены. Примените инструкции подключения и повторите проверку. Защита ещё не включена.',
        'installed_title' => 'Защита подключена',
        'installed_body' => 'Выбранный способ подключения прошёл проверки. Посмотрите покрытие защиты и откройте сайт.',
        'operation_done' => 'Действие выполнено',
        'operation_done_body' => 'Операция завершена. Результаты её проверок доступны ниже.',
        'not_verified' => 'Настройки сохранены — нужна проверка',
        'not_verified_body' => 'Одной записи файлов недостаточно. Проверьте, что защита посетителей работает на вашем хостинге.',
        'button_verify' => 'Проверить подключение снова',
        'open_site' => 'Открыть сайт',
        'edit_settings' => 'Изменить настройки',
        'coverage' => 'Покрытие защиты',
        'not_active' => 'Ещё не проверено',
        'active' => 'Включена',
        'locked_title' => 'Установщик закрыт',
        'locked_body' => 'Используйте персональный пакет установки или доступ, выданный администратором сайта.',
        'locked_footer' => 'Для просмотра и изменения настроек сайта требуется доступ.',
        'label_setup_code' => 'Код установки',
        'desc_setup_code' => 'Возьмите код в разделе «Сайты» панели KEHR.',
        'button_authorize' => 'Открыть установку',
        'setup_error' => 'Не удалось принять код установки. Проверьте код или получите новый пакет.',
        'setup_ready' => 'Данные подключения уже получены',
        'setup_ready_hint' => 'Они безопасно переданы для этой установки.',
        'label_document_root' => 'Публичная директория сайта',
        'desc_document_root' => 'Каталог, который отдаёт веб-сервер. Оставьте пустым для автоопределения.',
        'label_mount_path' => 'Префикс адреса сайта',
        'desc_mount_path' => 'Оставьте пустым для корня домена или укажите префикс, например /shop.',
        'label_integration_method' => 'Способ подключения',
        'desc_integration_method' => 'Автоматический выбор учитывает возможности хостинга. Проверьте найденное покрытие.',
        'integration_auto' => 'Автоматически',
        'integration_prepend' => 'Перед каждым PHP-запросом',
        'integration_entrypoint' => 'Выбранные PHP-файлы',
        'integration_static' => 'Шлюз для HTML-сайта',
        'integration_manual' => 'Ручное подключение',
        'label_browser_proof_enabled' => 'Запоминать проверку браузера',
        'desc_browser_proof_enabled' => 'Использовать защищённую cookie вашего сайта. Политика сайта по-прежнему проверяется для каждого защищённого запроса.',
        'busy' => 'Проверяем…',
        'update_pending' => 'Обновление подготавливается',
        'update_pending_body' => 'Текущая версия продолжает работать. Продолжите, чтобы проверить оставшиеся файлы и завершить обновление.',
        'continue_update' => 'Продолжить обновление',
        'connection_metadata' => 'Данные подключения',
        'setup_closed' => 'Установщик закрыт. Для изменений потребуется новый доступ.',
        'reconfigure_warning' => 'Настройки изменят существующее подключение. При ошибке установки восстановится прежняя конфигурация.',
        'check_not_run' => 'Проверка не выполнена',
        'check_unavailable' => 'Не удалось проверить окружение. Откройте технические подробности.',
        'required_mark' => 'Обязательно',
        'optional_mark' => 'Необязательно',
        'no_js' => 'Все настройки и действия доступны без JavaScript.',
    ],
];
$t = static fn (string $key): string => $translations[$uiLang][$key] ?? $translations['en'][$key] ?? $key;
$h = static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$logs = [];
$errors = [];
$statusCode = null;
$action = '';
$installer = new Installer($projectRoot);
$installer->setLogger(static function (string $level, string $message) use (&$logs): void {
    $logs[] = ['level' => $level, 'message' => $message];
});
$scan = $isAuthorized ? $installer->scan() : [];
$installationState = $runtime->getArray('installation');
$trustedDefaults = $runtime->getArray('trusted_proxy');
$assetsDefaults = $runtime->getArray('assets');
$assetsAutoDefaults = is_array($assetsDefaults['auto_update'] ?? null) ? $assetsDefaults['auto_update'] : [];
$moduleUpdateDefaults = $runtime->getArray('module_update');
$botBlockDefaults = $runtime->getArray('bot_blocking');
$cacheDefaults = $runtime->getArray('cache');
$cacheRedisDefaults = is_array($cacheDefaults['redis'] ?? null) ? $cacheDefaults['redis'] : [];
$basePathSeed = '/assets/.cache/' . Utils::randomToken(12);
$configuredBasePath = trim($runtime->getString('base_path'));
if ($configuredBasePath === '' || strtolower($configuredBasePath) === '/assets/.cache/ys_demo') {
    $configuredBasePath = $basePathSeed;
}
$runtimeStorageManaged = $runtime->getBool('runtime_storage_managed', true);

$defaults = [
    'site_key' => $runtime->getString('site_key'),
    'site_host' => Utils::resolveSiteHost($_SERVER, $runtime->getString('site_host')),
    'cloud_url' => $runtime->getString('cloud_base_url'),
    'base_path' => $configuredBasePath,
    'entrypoints' => '',
    'cms' => 'auto',
    'use_cms_presets' => '1',
    'runtime_env' => 'auto',
    'runtime_dir' => $runtimeStorageManaged ? '' : $runtime->getString('runtime_dir'),
    'cache_dir' => $runtimeStorageManaged ? '' : $runtime->getString('cache_dir'),
    'trusted_proxy_enabled' => (bool) ($trustedDefaults['enabled'] ?? false) ? '1' : '0',
    'trusted_proxy_provider' => is_string($trustedDefaults['provider'] ?? null) ? (string) $trustedDefaults['provider'] : 'none',
    'trusted_proxy_auto_ips' => (bool) ($trustedDefaults['auto_ips'] ?? true) ? '1' : '0',
    'trusted_proxy_cidrs' => is_array($trustedDefaults['trusted_cidrs'] ?? null)
        ? implode(', ', $trustedDefaults['trusted_cidrs'])
        : '',
    'trusted_proxy_ip_header' => is_string($trustedDefaults['ip_header'] ?? null)
        ? (string) $trustedDefaults['ip_header']
        : 'HTTP_X_FORWARDED_FOR',
    'trusted_proxy_proto_header' => is_string($trustedDefaults['proto_header'] ?? null)
        ? (string) $trustedDefaults['proto_header']
        : 'HTTP_X_FORWARDED_PROTO',
    'assets_auto_update_enabled' => (bool) ($assetsAutoDefaults['enabled'] ?? true) ? '1' : '0',
    'assets_auto_update_interval_sec' => (string) (
        is_numeric($assetsAutoDefaults['interval_sec'] ?? null)
            ? (int) $assetsAutoDefaults['interval_sec']
            : 900
    ),
    'module_auto_update_enabled' => (bool) ($moduleUpdateDefaults['enabled'] ?? true) ? '1' : '0',
    'module_auto_update_interval_sec' => (string) (
        is_numeric($moduleUpdateDefaults['interval_sec'] ?? null)
            ? (int) $moduleUpdateDefaults['interval_sec']
            : 21600
    ),
    'bot_block_mode' => is_string($botBlockDefaults['mode'] ?? null)
        ? (string) $botBlockDefaults['mode']
        : 'block',
    'bot_whitepage_dir' => is_string($botBlockDefaults['whitepage_dir'] ?? null)
        ? (string) $botBlockDefaults['whitepage_dir']
        : '',
    'cache_driver' => is_string($cacheDefaults['driver'] ?? null) ? (string) $cacheDefaults['driver'] : 'auto',
    'cache_prefix' => is_string($cacheDefaults['prefix'] ?? null) ? (string) $cacheDefaults['prefix'] : 'ys:',
    'cache_apcu_prefix' => is_string($cacheDefaults['apcu_prefix'] ?? null)
        ? (string) $cacheDefaults['apcu_prefix']
        : (
            is_string($cacheDefaults['prefix'] ?? null)
                ? (string) $cacheDefaults['prefix']
                : 'ys:'
        ),
    'cache_lock_wait_ms' => (string) (
        is_numeric($cacheDefaults['lock_wait_ms'] ?? null)
            ? (int) $cacheDefaults['lock_wait_ms']
            : 500
    ),
    'cache_lock_ttl_sec' => (string) (
        is_numeric($cacheDefaults['lock_ttl_sec'] ?? null)
            ? (int) $cacheDefaults['lock_ttl_sec']
            : 5
    ),
    'cache_redis_host' => is_string($cacheRedisDefaults['host'] ?? null) ? (string) $cacheRedisDefaults['host'] : '127.0.0.1',
    'cache_redis_port' => (string) (
        is_numeric($cacheRedisDefaults['port'] ?? null)
            ? (int) $cacheRedisDefaults['port']
            : 6379
    ),
    'cache_redis_db' => (string) (
        is_numeric($cacheRedisDefaults['db'] ?? null)
            ? (int) $cacheRedisDefaults['db']
            : 0
    ),
    'cache_redis_timeout_sec' => (string) (
        is_numeric($cacheRedisDefaults['timeout_sec'] ?? null)
            ? (float) $cacheRedisDefaults['timeout_sec']
            : 0.2
    ),
    'cache_redis_read_timeout_sec' => (string) (
        is_numeric($cacheRedisDefaults['read_timeout_sec'] ?? null)
            ? (float) $cacheRedisDefaults['read_timeout_sec']
            : 0.2
    ),
    'cache_redis_prefix' => is_string($cacheRedisDefaults['prefix'] ?? null)
        ? (string) $cacheRedisDefaults['prefix']
        : (
            is_string($cacheDefaults['prefix'] ?? null)
                ? (string) $cacheDefaults['prefix']
                : 'ys:'
        ),
    'probe_url' => (
        isset($_SERVER['HTTP_HOST'])
        && is_string($_SERVER['HTTP_HOST'])
        && trim($_SERVER['HTTP_HOST']) !== ''
    )
        ? (Utils::requestScheme($_SERVER, $trustedProxyCfg) . '://' . trim((string) $_SERVER['HTTP_HOST']))
        : '',
];
$defaults += [
    'document_root' => $runtime->getString('document_root'),
    'mount_path' => $runtime->getString('mount_path'),
    'integration_method' => (string) ($installationState['method'] ?? 'auto'),
    'browser_proof_enabled' => ((bool) ($runtime->getArray('browser_proof')['enabled'] ?? true)) ? '1' : '0',
];
if ($defaults['site_key'] === 'replace-with-site-key') { $defaults['site_key'] = ''; }
if ($defaults['cloud_url'] === 'https://cloud.example.com') { $defaults['cloud_url'] = ''; }
$hasSavedSecret = $runtime->getString('secret') !== '' && $runtime->getString('secret') !== 'replace-with-secret';
$hasInstallation = $installationState !== [] || $runtime->getArray('managed_entrypoints') !== [];
foreach (['site_key', 'site_host', 'cloud_url'] as $name) {
    if (is_string($setupCredentials[$name] ?? null)) { $defaults[$name] = $setupCredentials[$name]; }
}
$hasSavedSecret = $hasSavedSecret || $setupCredentialsReady;
$checkboxes = ['use_cms_presets', 'trusted_proxy_enabled', 'trusted_proxy_auto_ips', 'assets_auto_update_enabled', 'module_auto_update_enabled', 'browser_proof_enabled'];
if ($isAuthorized && is_array($_SESSION['ys_installer_draft'] ?? null)) {
    foreach ($defaults as $key => $value) {
        if (is_string($_SESSION['ys_installer_draft'][$key] ?? null)) { $defaults[$key] = $_SESSION['ys_installer_draft'][$key]; }
    }
}
$result = ($isAuthorized || $setupCompleted) && is_array($_SESSION['ys_installer_result'] ?? null) ? $_SESSION['ys_installer_result'] : null;
unset($_SESSION['ys_installer_result']);
if ($result !== null) {
    $statusCode = (int) ($result['code'] ?? 1);
    $action = (string) ($result['action'] ?? '');
    $errors = is_array($result['errors'] ?? null) ? $result['errors'] : [];
    $logs = is_array($result['logs'] ?? null) ? $result['logs'] : [];
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && $isAuthorized) {
    $action = $postText('action');
    $submittedSecret = $postText('secret');
    $submittedRedisPassword = $postText('cache_redis_password');
    if (!hash_equals($csrf, $postText('csrf'))) {
        $errors['_form'] = $t('csrf_failed');
    } elseif ($action === 'install') {
        foreach ($defaults as $key => $value) {
            $defaults[$key] = in_array($key, $checkboxes, true) ? ($postText($key) === '1' ? '1' : '0') : $postText($key, $value);
            if (strlen($defaults[$key]) > 8192 || (isset($_POST[$key]) && !is_string($_POST[$key]))) {
                $errors[$key] = $t('field_invalid');
                $defaults[$key] = $value;
            }
        }
        foreach (['site_key', 'site_host', 'cloud_url'] as $key) {
            if ($defaults[$key] === '') { $errors[$key] = $t('field_required'); }
        }
        if ($submittedSecret === '' && !$hasSavedSecret) { $errors['secret'] = $t('field_required'); }
        if ($defaults['cloud_url'] !== '' && Utils::validateCloudBaseUrl($defaults['cloud_url'], $runtime->getArray('cloud_url_policy')) !== null) {
            $errors['cloud_url'] = $t('cloud_invalid');
        }
        if ($defaults['bot_block_mode'] === 'whitepage_dir' && $defaults['bot_whitepage_dir'] === '') {
            $errors['bot_whitepage_dir'] = $t('field_required');
        }
    } elseif (in_array($action, ['uninstall', 'disable', 'rollback'], true) && $postText('confirm_action') !== $action) {
        $errors['_form'] = $t('confirm_required');
    }

    $statusCode = 1;
    if ($errors === []) {
        $installer->resetLogs();
        try {
            if ($action === 'install') {
                $options = $defaults;
                // The package pins its credentials and cloud; submitted fields cannot redirect the secret.
                if ($setupCredentialsReady) { $options = array_replace($options, $setupCredentials); }
                foreach (['runtime_dir', 'cache_dir', 'document_root'] as $key) {
                    if ($options[$key] === '') { unset($options[$key]); }
                }
                if ($submittedSecret !== '' && !$setupCredentialsReady) { $options['secret'] = $submittedSecret; }
                if ($submittedRedisPassword !== '') { $options['cache_redis_password'] = $submittedRedisPassword; }
                $statusCode = $installer->install($options);
                if ($statusCode === 0 && $setupCredentialsReady) {
                    $setupAccess->complete();
                    $_SESSION['ys_setup_finished'] = true;
                }
            } elseif ($action === 'test') {
                $statusCode = $installer->test(['probe_url' => $postText('probe_url', $defaults['probe_url'])]);
                if ($statusCode === 0 && $setupCredentialsReady
                    && (RuntimeConfig::fromFile($configPath)->getArray('installation')['status'] ?? '') === 'active') {
                    $setupAccess->complete();
                    $_SESSION['ys_setup_finished'] = true;
                }
            } elseif ($action === 'update-assets') {
                $statusCode = $installer->updateAssets();
            } elseif ($action === 'update-module') {
                $statusCode = $installer->updateModule();
            } elseif ($action === 'uninstall') {
                $statusCode = $installer->uninstall();
            } elseif ($action === 'disable' && method_exists($installer, 'disable')) {
                $statusCode = $installer->disable();
            } elseif ($action === 'rollback' && method_exists($installer, 'rollback')) {
                $statusCode = $installer->rollback();
            } else {
                $errors['_form'] = $t('unknown_action');
            }
        } catch (Throwable $exception) {
            $errors['_form'] = $t('operation_failed');
        }
    }
    if ($statusCode === 1 && $errors === []) { $errors['_form'] = $t('operation_failed'); }
    if ($statusCode === 1 && $action === 'install' && !$hasSavedSecret) {
        $errors['secret'] = $t('secret_again');
    }
    // PRG retains ordinary input, never Site/Redis secrets or passwords.
    $_SESSION['ys_installer_draft'] = $defaults;
    $redactions = array_filter([$submittedSecret, $submittedRedisPassword, $runtime->getString('secret'), $expectedToken, $defaults['site_key']]);
    foreach ($logs as &$line) { $line['message'] = str_replace($redactions, '[redacted]', (string) ($line['message'] ?? '')); }
    unset($line);
    $_SESSION['ys_installer_result'] = ['code' => $statusCode, 'action' => $action, 'errors' => $errors, 'logs' => array_slice($logs, -100)];
    $redirect(['lang' => $uiLang, 'result' => '1']);
}

$preflightChecks = [];
if ($isAuthorized) {
    try {
        $scan = $installer->scan(array_filter($defaults, static fn ($value) => $value !== ''));
        $preflightChecks = $installer->preflight(array_filter($defaults, static fn ($value) => $value !== ''));
    } catch (Throwable $exception) {
        $preflightChecks[] = ['key' => 'environment', 'label' => $t('check_not_run'), 'ok' => false, 'detail' => $t('check_unavailable')];
    }
}
$runtimeScan = is_array($scan['runtime'] ?? null) ? $scan['runtime'] : [];
$runtimeKind = (string) ($runtimeScan['kind'] ?? 'unknown');
$runtimeHints = is_array($runtimeScan['manual_routing_hints'] ?? null) ? $runtimeScan['manual_routing_hints'] : [];
$cmsDetected = (string) ($scan['cms'] ?? $scan['cms_detected'] ?? 'generic');
$cmsLabel = ['generic' => 'PHP / HTML', 'wordpress' => 'WordPress', 'laravel' => 'Laravel', 'symfony' => 'Symfony'][$cmsDetected] ?? $cmsDetected;
$runtimeLabel = ['php_builtin' => $t('runtime_php_builtin'), 'unknown' => $t('runtime_unknown'), 'nginx' => 'Nginx', 'apache' => 'Apache', 'litespeed' => 'LiteSpeed', 'caddy' => 'Caddy', 'iis' => 'IIS'][$runtimeKind] ?? $runtimeKind;
$preflightFailures = count(array_filter($preflightChecks, static fn (array $check): bool => !($check['ok'] ?? false)));
$state = (string) ($installationState['status'] ?? '');
$isActive = $state === 'active';
$updatePending = $statusCode === 2 && in_array($action, ['update-assets', 'update-module'], true);
$needsAction = (!$updatePending && $statusCode === 2) || $state === 'needs_action' || $state === 'staged';
$showResult = $result !== null && $errors === [];
$showMaintenance = $isAuthorized && ($hasInstallation || isset($_GET['maintenance']));
$step = $showResult ? 3 : 1;
$resultTitle = $updatePending ? 'update_pending' : ($statusCode === 2 ? 'needs_action' : (($action === 'install' || $action === 'test') ? ($isActive ? 'installed_title' : 'not_verified') : 'operation_done'));
$resultBody = $updatePending ? 'update_pending_body' : ($statusCode === 2 ? 'needs_action_body' : (($action === 'install' || $action === 'test') ? ($isActive ? 'installed_body' : 'not_verified_body') : 'operation_done_body'));
$siteLink = $defaults['mount_path'] === '' ? '/' : $defaults['mount_path'] . '/';
if (!str_starts_with($siteLink, '/') || str_starts_with($siteLink, '//') || preg_match('/[\\\\\x00-\x20\x7f]/', $siteLink)) { $siteLink = '/'; }
if (!$enabled && !$setupAvailable && !$setupCompleted) { http_response_code(403); }
elseif (!$isAuthorized && !$setupCompleted) { http_response_code(401); }

$selects = [
    'cms' => ['auto' => $t('option_auto'), 'wordpress' => 'WordPress', 'laravel' => 'Laravel', 'symfony' => 'Symfony', 'generic' => 'PHP / HTML'],
    'runtime_env' => ['auto' => $t('option_auto'), 'apache' => 'Apache', 'litespeed' => 'LiteSpeed', 'nginx' => 'Nginx', 'iis' => 'IIS', 'caddy' => 'Caddy', 'php_builtin' => 'PHP built-in', 'unknown' => 'Unknown'],
    'integration_method' => ['auto' => $t('integration_auto'), 'prepend' => $t('integration_prepend'), 'entrypoint' => $t('integration_entrypoint'), 'static' => $t('integration_static'), 'manual' => $t('integration_manual')],
    'bot_block_mode' => ['block' => $t('bot_mode_block'), 'whitepage_dir' => $t('bot_mode_whitepage_dir')],
    'trusted_proxy_provider' => ['none' => '—', 'cloudflare' => 'Cloudflare', 'cloudfront' => 'CloudFront', 'fastly' => 'Fastly'],
    'cache_driver' => ['auto' => $t('cache_driver_auto'), 'file' => 'File', 'apcu' => 'APCu', 'redis' => 'Redis'],
];
$groups = [
    'group_connection' => ['document_root', 'mount_path', 'integration_method', 'cms', 'runtime_env', 'entrypoints', 'base_path', 'probe_url'],
    'group_protection' => ['browser_proof_enabled', 'use_cms_presets', 'bot_block_mode', 'bot_whitepage_dir'],
    'group_proxy' => ['trusted_proxy_enabled', 'trusted_proxy_provider', 'trusted_proxy_auto_ips', 'trusted_proxy_cidrs', 'trusted_proxy_ip_header', 'trusted_proxy_proto_header'],
    'group_storage' => ['cache_driver', 'runtime_dir', 'cache_dir', 'cache_prefix', 'cache_apcu_prefix', 'cache_lock_wait_ms', 'cache_lock_ttl_sec', 'cache_redis_host', 'cache_redis_port', 'cache_redis_db', 'cache_redis_password', 'cache_redis_timeout_sec', 'cache_redis_read_timeout_sec', 'cache_redis_prefix'],
    'group_updates' => ['assets_auto_update_enabled', 'assets_auto_update_interval_sec', 'module_auto_update_enabled', 'module_auto_update_interval_sec'],
];
$required = ['site_host', 'site_key', 'cloud_url', 'setup_code'];
if ($setupError !== '') { $errors['setup_code'] = $t('setup_error'); }
if (!$hasSavedSecret && !($setupCredentialsReady ?? false)) { $required[] = 'secret'; }
$field = static function (string $name) use ($h, $t, $uiLang, $translations, $defaults, $errors, $selects, $checkboxes, $required): void {
    $label = $t('label_' . $name);
    $description = $t('desc_' . $name);
    $error = (string) ($errors[$name] ?? '');
    $value = (string) ($defaults[$name] ?? '');
    $isCheckbox = in_array($name, $checkboxes, true);
    $isPassword = in_array($name, ['secret', 'cache_redis_password', 'setup_code'], true);
    $conditional = str_starts_with($name, 'cache_redis_') ? ' data-visible-when="cache_driver:redis"' : ($name === 'bot_whitepage_dir' ? ' data-visible-when="bot_block_mode:whitepage_dir"' : '');
    $attrs = ' id="' . $h($name) . '" name="' . $h($name) . '" aria-describedby="' . $h($name) . '-help' . ($error !== '' ? ' ' . $h($name) . '-error' : '') . '"';
    if (in_array($name, $required, true)) { $attrs .= ' required'; }
    if ($error !== '') { $attrs .= ' aria-invalid="true"'; }
    echo '<div class="field' . ($isCheckbox ? ' checkbox-field' : '') . '"' . $conditional . '>';
    if (!$isCheckbox) { echo '<label for="' . $h($name) . '">' . $h($label) . '</label>'; }
    if (isset($selects[$name])) {
        echo '<select' . $attrs . '>';
        foreach ($selects[$name] as $option => $text) {
            echo '<option value="' . $h($option) . '"' . ($option === $value ? ' selected' : '') . '>' . $h($text) . '</option>';
        }
        echo '</select>';
    } elseif ($isCheckbox) {
        echo '<label class="check-label" for="' . $h($name) . '"><input type="checkbox" value="1"' . $attrs . ($value === '1' ? ' checked' : '') . '><span>' . $h($label) . '</span></label>';
    } else {
        $placeholder = $translations[$uiLang]['placeholder_' . $name] ?? '';
        $numeric = preg_match('/(?:_sec|_ms|_port|_db)$/', $name) === 1;
        $type = $isPassword ? 'password' : ($name === 'cloud_url' || $name === 'probe_url' ? 'url' : ($numeric ? 'number' : 'text'));
        echo '<input' . $attrs . ' type="' . $type . '"' . (!$isPassword ? ' value="' . $h($value) . '"' : ' autocomplete="new-password"') . ($numeric ? ' min="0" step="any"' : '') . ($placeholder !== '' ? ' placeholder="' . $h($placeholder) . '"' : '') . '>';
    }
    echo '<p class="field-help" id="' . $h($name) . '-help">' . $h($description) . '</p>';
    if ($error !== '') { echo '<p class="field-error" id="' . $h($name) . '-error">' . $h($error) . '</p>'; }
    echo '</div>';
};
$csrfFields = static function () use ($h, $csrf, $uiLang): void {
    echo '<input type="hidden" name="csrf" value="' . $h($csrf) . '"><input type="hidden" name="ui_lang" value="' . $h($uiLang) . '">';
};
?>
<!doctype html>
<html lang="<?= $h($uiLang) ?>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <title><?= $h($t('page_title')) ?></title>
    <script nonce="<?= $h($nonce) ?>">try { var theme=localStorage.getItem('ys_installer_theme'); if(theme==='light'||theme==='dark') document.documentElement.dataset.theme=theme; } catch(e) {}</script>
    <style nonce="<?= $h($nonce) ?>"><?php readfile(__DIR__ . '/installer.css'); ?></style>
</head>
<body>
<div class="shell">
    <header class="topbar">
        <a class="brand" href="<?= $h($requestPath) ?>" aria-label="YourShield">
            <svg viewBox="0 0 32 36" aria-hidden="true"><path d="M16 2 29 7v10c0 8-6 13-13 17C9 30 3 25 3 17V7Z"/><path d="m10 17 4 4 8-9"/></svg>
            <span>YourShield<small><?= $h($t('subtitle')) ?></small></span>
        </a>
        <div class="preferences">
            <nav class="languages" aria-label="<?= $h($t('lang_label')) ?>">
                <?php foreach (['ru' => 'RU', 'en' => 'EN'] as $lang => $label): ?>
                    <a href="<?= $h($requestPath . '?lang=' . $lang) ?>" lang="<?= $lang ?>" <?= $uiLang === $lang ? 'aria-current="true"' : '' ?>><?= $label ?></a>
                <?php endforeach; ?>
            </nav>
            <label class="sr-only" for="theme_mode"><?= $h($t('theme_label')) ?></label>
            <select id="theme_mode" class="theme-select">
                <?php foreach (['auto', 'light', 'dark'] as $theme): ?><option value="<?= $theme ?>"><?= $h($t('theme_' . $theme)) ?></option><?php endforeach; ?>
            </select>
        </div>
    </header>

    <main id="main-content">
    <?php if (!$isAuthorized && !$setupCompleted): ?>
        <section class="panel locked-panel">
            <span class="eyebrow"><?= $h($t('step_connect')) ?></span>
            <h1><?= $h($t(($setupAvailable ?? false) ? 'intro_title' : 'locked_title')) ?></h1>
            <p class="lead"><?= $h($t(($setupAvailable ?? false) ? 'desc_setup_code' : 'locked_body')) ?></p>
            <?php if (($setupAvailable ?? false)): ?>
                <?php if (($setupError ?? '') !== ''): ?><div class="notice danger" role="alert"><?= $h($t('setup_error')) ?></div><?php endif; ?>
                <form method="post" class="setup-form">
                    <?php $csrfFields(); ?>
                    <?php $field('setup_code'); ?>
                    <button class="button primary" name="action" value="authorize" type="submit"><?= $h($t('button_authorize')) ?></button>
                </form>
            <?php else: ?>
                <p class="muted"><?= $h($t(!$enabled ? 'installer_disabled' : 'unauthorized')) ?></p>
            <?php endif; ?>
            <p class="footnote"><?= $h($t('locked_footer')) ?></p>
        </section>
    <?php else: ?>
        <ol class="steps" aria-label="<?= $h($t('page_title')) ?>">
            <?php foreach ([1 => 'step_connect', 2 => 'step_review', 3 => 'step_done'] as $number => $label): ?>
                <li data-step-marker="<?= $number ?>" <?= $step === $number ? 'aria-current="step"' : '' ?>><span class="step-number"><?= $number ?></span><span><?= $h($t($label)) ?></span></li>
            <?php endforeach; ?>
        </ol>
        <?php if ($errors !== []): ?>
            <section class="notice danger error-summary" role="alert" tabindex="-1" id="error-summary" aria-labelledby="error-title">
                <h2 id="error-title"><?= $h($t('errors_title')) ?></h2>
                <ul><?php foreach ($errors as $name => $error): ?><li><?php if ($name !== '_form'): ?><a href="#<?= $h($name) ?>"><?= $h($t('label_' . $name)) ?>: <?= $h((string) $error) ?></a><?php else: ?><?= $h((string) $error) ?><?php endif; ?></li><?php endforeach; ?></ul>
            </section>
        <?php endif; ?>

        <?php if ($showResult): ?>
            <section class="panel result-panel">
                <span class="eyebrow"><?= $h($t('step_done')) ?></span>
                <h1><?= $h($t($resultTitle)) ?></h1>
                <p class="lead"><?= $h($t($resultBody)) ?></p>
                <?php if ($isActive): ?><p class="verified-mark"><?= $h($t('active')) ?> · <?= $h($defaults['site_host']) ?></p><?php endif; ?>
                <?php if (!empty($installationState['coverage'])): ?>
                    <h2><?= $h($t('coverage')) ?></h2>
                    <ul class="coverage-list"><?php foreach ((array) $installationState['coverage'] as $coverage): ?><?php if (is_scalar($coverage)): ?><li><?= $h((string) $coverage) ?></li><?php endif; ?><?php endforeach; ?></ul>
                <?php endif; ?>
                <div class="actions">
                    <?php if ($isActive): ?><a class="button primary" href="<?= $h($siteLink) ?>"><?= $h($t('open_site')) ?></a><?php endif; ?>
                    <?php if ($isAuthorized): ?><a class="button <?= $isActive ? 'secondary' : 'primary' ?>" href="<?= $h($requestPath . '?lang=' . $uiLang) ?>"><?= $h($t('edit_settings')) ?></a><?php endif; ?>
                </div>
                <?php if ($updatePending && $isAuthorized): ?><form method="post" class="actions"><?php $csrfFields(); ?><button class="button primary" name="action" value="<?= $h($action) ?>"><?= $h($t('continue_update')) ?></button></form><?php endif; ?>
                <?php if ($setupCompleted): ?><p class="footnote"><?= $h($t('setup_closed')) ?></p><?php endif; ?>
            </section>
        <?php else: ?>
            <form method="post" id="install-form" class="panel install-panel" data-errors="<?= $errors !== [] ? '1' : '0' ?>">
                <?php $csrfFields(); ?>
                <section data-wizard-step="1" aria-labelledby="connection-title">
                    <span class="eyebrow"><?= $h($t('step_connect')) ?></span>
                    <h1 id="connection-title" tabindex="-1"><?= $h($t('intro_title')) ?></h1>
                    <p class="lead"><?= $h($t('intro_body')) ?></p>
                    <div class="site-summary"><span><?= $h($t('environment')) ?></span><strong><?= $h($defaults['site_host'] ?: '—') ?></strong><small><?= $h($cmsLabel) ?> · <?= $h($runtimeLabel) ?></small></div>
                    <?php if ($setupCredentialsReady): ?>
                        <div class="notice info"><strong><?= $h($t('setup_ready')) ?></strong><p><?= $h($t('setup_ready_hint')) ?></p></div>
                        <details class="connection-metadata"><summary><?= $h($t('connection_metadata')) ?></summary>
                            <dl><?php foreach (['site_host', 'site_key', 'cloud_url'] as $name): ?><dt><?= $h($t('label_' . $name)) ?></dt><dd><?= $h($defaults[$name]) ?></dd><?php endforeach; ?></dl>
                        </details>
                    <?php else: ?>
                        <fieldset class="credentials"><legend><?= $h($t('step_connect')) ?></legend>
                            <p class="muted"><?= $h($t('connection_hint')) ?></p>
                            <div class="fields-grid">
                                <?php foreach (['site_host', 'site_key', 'secret', 'cloud_url'] as $name) { $field($name); } ?>
                            </div>
                        </fieldset>
                    <?php endif; ?>
                    <div class="actions next-action" hidden><button class="button primary" type="button" data-next><?= $h($t('next')) ?><span aria-hidden="true">→</span></button></div>
                </section>
                <section data-wizard-step="2" aria-labelledby="review-title">
                    <div class="review-heading"><span class="eyebrow"><?= $h($t('step_review')) ?></span><h2 id="review-title" tabindex="-1"><?= $h($t('review_title')) ?></h2><p class="lead"><?= $h($t('review_body')) ?></p></div>
                    <?php if ($hasInstallation): ?><p class="notice info"><?= $h($t('reconfigure_warning')) ?></p><?php endif; ?>
                    <div class="site-summary"><span><?= $h($t('environment')) ?></span><strong><?= $h($defaults['site_host'] ?: '—') ?></strong><small><?= $h($cmsLabel) ?> · <?= $h($runtimeLabel) ?></small></div>
                    <details class="advanced" id="advanced-settings" <?= count(array_diff(array_keys($errors), ['_form', 'site_host', 'site_key', 'secret', 'cloud_url'])) > 0 ? 'open' : '' ?>>
                        <summary><span><?= $h($t('advanced_settings')) ?><small><?= $h($t('advanced_hint')) ?></small></span></summary>
                        <?php foreach ($groups as $group => $fields): ?>
                            <fieldset class="settings-group"><legend><?= $h($t($group)) ?></legend><div class="fields-grid">
                                <?php foreach ($fields as $name) { $field($name); } ?>
                            </div></fieldset>
                        <?php endforeach; ?>
                    </details>
                    <div class="actions form-actions">
                        <button class="button secondary" type="button" data-back hidden><?= $h($t('back')) ?></button>
                        <button class="button primary" name="action" value="install" type="submit" data-busy="<?= $h($t('busy')) ?>"><?= $h($t('button_install')) ?></button>
                    </div>
                </section>
                <noscript><p class="footnote"><?= $h($t('no_js')) ?></p></noscript>
            </form>
        <?php endif; ?>

        <?php if ($needsAction): ?>
            <section class="panel action-panel">
                <h2><?= $h($t('needs_action')) ?></h2><p><?= $h($t('needs_action_body')) ?></p>
                <?php $notes = $installationState['notes'] ?? $runtimeHints; if (is_string($notes)) { $notes = [$notes]; } ?>
                <?php foreach (is_array($notes) ? $notes : [] as $note): ?><?php if (is_scalar($note)): ?><pre><?= $h((string) $note) ?></pre><?php endif; ?><?php endforeach; ?>
                <form method="post"><?php $csrfFields(); ?><input type="hidden" name="probe_url" value="<?= $h($defaults['probe_url']) ?>"><button name="action" value="test" class="button primary"><?= $h($t('button_verify')) ?></button></form>
            </section>
        <?php endif; ?>

        <?php if ($showMaintenance): ?>
            <details class="panel maintenance" id="maintenance">
                <summary><?= $h($t('maintenance')) ?></summary><p class="muted"><?= $h($t('maintenance_hint')) ?></p>
                <form method="post" class="actions"><?php $csrfFields(); ?><input type="hidden" name="probe_url" value="<?= $h($defaults['probe_url']) ?>">
                    <button class="button secondary" name="action" value="test"><?= $h($t('button_test')) ?></button>
                    <button class="button secondary" name="action" value="update-assets"><?= $h($t('button_update_assets')) ?></button>
                    <button class="button secondary" name="action" value="update-module"><?= $h($t('button_update_module')) ?></button>
                </form>
                <?php foreach (['disable', 'rollback', 'uninstall'] as $operation): ?>
                    <?php if ($operation !== 'uninstall' && !method_exists($installer, $operation)) { continue; } ?>
                    <details class="destructive"><summary><?= $h($t($operation . '_title')) ?></summary>
                        <form method="post"><?php $csrfFields(); ?>
                            <label class="check-label" for="confirm_<?= $operation ?>"><input id="confirm_<?= $operation ?>" type="checkbox" name="confirm_action" value="<?= $operation ?>" required><span><?= $h($t('confirm_' . $operation)) ?></span></label>
                            <button class="button danger-button" name="action" value="<?= $operation ?>"><?= $h($t('button_' . $operation)) ?></button>
                        </form>
                    </details>
                <?php endforeach; ?>
            </details>
        <?php endif; ?>
        <details class="diagnostics" <?= $errors !== [] ? 'open' : '' ?>>
            <summary><?= $h($t('details')) ?><?php if ($preflightFailures > 0): ?><span class="count"><?= $preflightFailures ?></span><?php endif; ?></summary>
            <h2><?= $h($t('preflight_title')) ?></h2>
            <ul class="check-list"><?php foreach ($preflightChecks as $check): ?><li><span class="check-state <?= ($check['ok'] ?? false) ? 'ok' : 'fail' ?>"><?= $h($t(($check['ok'] ?? false) ? 'state_ok' : 'state_fail')) ?></span><div><strong><?= $h((string) ($check['label'] ?? '')) ?></strong><small><?= $h((string) ($check['detail'] ?? '')) ?></small></div></li><?php endforeach; ?></ul>
            <?php if ($runtimeHints !== []): ?><h3><?= $h($t('manual_routing_hints')) ?></h3><pre><?= $h(implode("\n", array_filter($runtimeHints, 'is_string'))) ?></pre><?php endif; ?>
            <?php if ($statusCode !== null): ?><p><?= $h($t('exit_code')) ?> <?= $statusCode ?></p><?php endif; ?>
            <?php if ($logs !== []): ?><h3><?= $h($t('logs_title')) ?></h3><pre><?php foreach ($logs as $line): ?>[<?= $h((string) ($line['level'] ?? 'info')) ?>] <?= $h((string) ($line['message'] ?? '')) . "\n" ?><?php endforeach; ?></pre><?php endif; ?>
            <?php if ($defaults['assets_auto_update_enabled'] !== '1' || $defaults['module_auto_update_enabled'] !== '1'): ?>
                <h3><?= $h($t('cron_hint_disabled')) ?></h3><pre><?= $h('php ' . escapeshellarg($moduleRoot . '/updater.php')) . "\n" . $h('php ' . escapeshellarg($moduleRoot . '/module_updater.php')) ?></pre>
            <?php endif; ?>
        </details>
    <?php endif; ?>
    </main>
    <footer class="page-footer"><span>YourShield</span><span><?= $h($t('locked_footer')) ?></span></footer>
</div>
<script nonce="<?= $h($nonce) ?>"><?php readfile(__DIR__ . '/installer.js'); ?></script>
</body>
</html>
