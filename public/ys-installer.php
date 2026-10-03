<?php
declare(strict_types=1);

$ysInstallerModule = dirname(__DIR__) . '/yourshield';
$ysInstallerRelease = require $ysInstallerModule . '/management_loader.php';
$ysInstallerEntry = rtrim((string) $ysInstallerRelease, '/\\') . '/installer.php';
if (!is_file($ysInstallerEntry) || is_link($ysInstallerEntry)) {
    http_response_code(503);
    header('Cache-Control: no-store');
    exit('YourShield installer is unavailable. Restore the complete installation package.');
}
require $ysInstallerEntry;
