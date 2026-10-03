<?php
declare(strict_types=1);

$ysCodeRoot = dirname(__DIR__);
$ysStableRoot = defined('YS_MODULE_ROOT') && is_string(constant('YS_MODULE_ROOT'))
    ? rtrim((string) constant('YS_MODULE_ROOT'), '/\\')
    : $ysCodeRoot;
$ysIsStableAutoload = strcasecmp(
    str_replace('\\', '/', $ysCodeRoot),
    str_replace('\\', '/', $ysStableRoot)
) === 0;
$ysManagementLoader = $ysStableRoot . '/management_loader.php';
$ysStableVersionPath = $ysStableRoot . '/version.txt';
$ysStableVersion = is_file($ysStableVersionPath) && !is_link($ysStableVersionPath)
    ? @file_get_contents($ysStableVersionPath)
    : false;
$ysBridgePendingVersion = is_string($ysStableVersion)
    && in_array(trim($ysStableVersion), ['1.0.0', '1.0.1', '1.0.1-bridge'], true);
$ysNeedsManagementLoader = file_exists($ysStableRoot . '/.module-current')
    || is_link($ysStableRoot . '/.module-current')
    || $ysBridgePendingVersion;
if ($ysIsStableAutoload
    && $ysNeedsManagementLoader
    && is_file($ysManagementLoader)
    && !is_link($ysManagementLoader)
) {
    require_once $ysManagementLoader;
    return;
}
if ($ysIsStableAutoload && $ysBridgePendingVersion) {
    spl_autoload_register(static function (string $class): void {
        if ($class !== 'YourShield\\Installer') {
            return;
        }
        $message = 'YourShield management is unavailable until the bridge update activates a full release.';
        if (PHP_SAPI === 'cli') {
            fwrite(STDERR, $message . PHP_EOL);
        } else {
            http_response_code(503);
            if (!headers_sent()) {
                header('Content-Type: text/plain; charset=utf-8');
                header('Cache-Control: no-store');
            }
            echo $message;
        }
        exit(1);
    }, true, true);
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'YourShield\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    if ($relative === false || $relative === '') {
        return;
    }

    $path = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require_once $path;
    }
});

// Stable bootstrap wrappers survive immutable upgrades. Enforce ownership in
// the active release they load, before any wrapper can continue to config/app.
// Library-only consumers without a pinned runtime keep ownershipIssue() pure.
if (defined('YS_MODULE_ROOT')) {
    $ysOwnershipIssue = \YourShield\Utils::ownershipIssue($ysStableRoot . '/config.local.php');
    if ($ysOwnershipIssue !== null) {
        error_log('[YourShield] ' . $ysOwnershipIssue);
        if (PHP_SAPI !== 'cli') {
            http_response_code(503);
            if (!headers_sent()) {
                header('Content-Type: text/plain; charset=utf-8');
                header('Cache-Control: no-store');
            }
            echo 'Service temporarily unavailable.';
        }
        exit(1);
    }
}
