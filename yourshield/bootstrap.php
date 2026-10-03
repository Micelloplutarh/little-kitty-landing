<?php
declare(strict_types=1);

if (!defined('YS_MODULE_ROOT')) {
    define('YS_MODULE_ROOT', __DIR__);
}
require_once (string) constant('YS_MODULE_ROOT') . '/release_loader.php';
if (!defined('YS_RELEASE_ROOT')) {
    define('YS_RELEASE_ROOT', ys_resolve_module_release_root((string) constant('YS_MODULE_ROOT')));
}
$releaseRoot = (string) constant('YS_RELEASE_ROOT');

require_once $releaseRoot . '/lib/autoload.php';

use YourShield\Agent;
use YourShield\RuntimeConfig;
use YourShield\Utils;

// Keep this guard as well as active-release autoload enforcement: an older
// release selected during rollback may have an autoload without the guard.
$ownershipIssue = Utils::ownershipIssue((string) constant('YS_MODULE_ROOT') . '/config.local.php');
if ($ownershipIssue !== null) {
    error_log('[YourShield] ' . $ownershipIssue);
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

$config = RuntimeConfig::fromFile($releaseRoot . '/config.php');
if (class_exists(\YourShield\InstallProbe::class)) {
    \YourShield\InstallProbe::respond($config, $_SERVER);
}
$enabled = $config->getBool('enabled', true);
if (!$enabled) {
    return;
}

$agent = new Agent($config);
$agent->run($_SERVER);
