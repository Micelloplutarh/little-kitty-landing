<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

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

$ownershipIssue = Utils::ownershipIssue((string) constant('YS_MODULE_ROOT') . '/config.local.php');
if ($ownershipIssue !== null) {
    fwrite(STDERR, 'YourShield: ' . $ownershipIssue . PHP_EOL);
    exit(1);
}

$config = RuntimeConfig::fromFile($releaseRoot . '/config.php');
$agent = new Agent($config);
$exitCode = $agent->updateModule();
exit($exitCode);
