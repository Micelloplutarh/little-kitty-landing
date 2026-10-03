<?php
declare(strict_types=1);

// Stable shim: uninstall preserves this file while PHP workers cache old INI settings.
if (PHP_SAPI === 'cli' || !is_file(__DIR__ . '/config.local.php')) {
    return;
}
$ysPrependUid = null;
if (DIRECTORY_SEPARATOR !== '\\') {
    if (function_exists('posix_geteuid')) {
        $ysPrependUid = posix_geteuid();
    } else {
        $ysPrependProbe = @tempnam(sys_get_temp_dir(), '.ys-owner-');
        $ysPrependUid = is_string($ysPrependProbe) ? fileowner($ysPrependProbe) : false;
        if (is_string($ysPrependProbe)) {
            @unlink($ysPrependProbe);
        }
    }
    if (!is_int($ysPrependUid) || $ysPrependUid === 0 || fileowner(__DIR__ . '/config.local.php') !== $ysPrependUid) {
        http_response_code(503);
        exit;
    }
}
$ysPrependLocal = require __DIR__ . '/config.local.php';
$ysPrependApp = (string) ($ysPrependLocal['application_root'] ?? $ysPrependLocal['public_root'] ?? '');
$ysPrependScript = realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? ''));
// These exact scripts enforce installer/validator authentication themselves.
foreach ([$ysPrependApp . '/ys-install.php', $ysPrependApp . '/ys-validate.php', dirname(__DIR__) . '/public/ys-installer.php'] as $ysPrependMaintenance) {
    if ($ysPrependScript !== false && $ysPrependScript === realpath($ysPrependMaintenance)) {
        return;
    }
}
if (!defined('YS_MODULE_ROOT')) {
    define('YS_MODULE_ROOT', __DIR__);
}
require_once __DIR__ . '/release_loader.php';
if (!defined('YS_RELEASE_ROOT')) {
    define('YS_RELEASE_ROOT', ys_resolve_module_release_root(__DIR__));
}
require_once (string) constant('YS_RELEASE_ROOT') . '/bootstrap.php';
