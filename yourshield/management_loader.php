<?php
declare(strict_types=1);

if (!defined('YS_MODULE_ROOT')) {
    define('YS_MODULE_ROOT', __DIR__);
}
$ysModuleRoot = rtrim((string) constant('YS_MODULE_ROOT'), '/\\');

require_once $ysModuleRoot . '/release_loader.php';
if (!defined('YS_RELEASE_ROOT')) {
    define('YS_RELEASE_ROOT', ys_resolve_module_release_root($ysModuleRoot));
}
$ysReleaseLib = rtrim((string) constant('YS_RELEASE_ROOT'), '/\\') . '/lib';
$ysFlatVersionPath = $ysModuleRoot . '/version.txt';
$ysFlatVersion = is_file($ysFlatVersionPath) && !is_link($ysFlatVersionPath)
    ? @file_get_contents($ysFlatVersionPath)
    : false;
$ysManagementPending = rtrim((string) constant('YS_RELEASE_ROOT'), '/\\') === $ysModuleRoot
    && is_string($ysFlatVersion)
    && in_array(trim($ysFlatVersion), ['1.0.0', '1.0.1', '1.0.1-bridge'], true);

if ($ysManagementPending) {
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

spl_autoload_register(static function (string $class) use ($ysReleaseLib): void {
    $prefix = 'YourShield\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    if ($relative === false || $relative === '') {
        return;
    }

    $path = $ysReleaseLib . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path) && !is_link($path)) {
        require_once $path;
    }
});

return (string) constant('YS_RELEASE_ROOT');
