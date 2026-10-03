<?php
declare(strict_types=1);

if (!defined('YS_MODULE_ROOT')) {
    define('YS_MODULE_ROOT', __DIR__);
}
require_once (string) constant('YS_MODULE_ROOT') . '/release_loader.php';
if (!defined('YS_RELEASE_ROOT')) {
    define('YS_RELEASE_ROOT', ys_resolve_module_release_root((string) constant('YS_MODULE_ROOT')));
}
if ((string) constant('YS_RELEASE_ROOT') !== __DIR__ && is_file((string) constant('YS_RELEASE_ROOT') . '/gateway.php')) {
    require (string) constant('YS_RELEASE_ROOT') . '/gateway.php';
    return;
}
require_once (string) constant('YS_RELEASE_ROOT') . '/bootstrap.php';

// This gateway serves only HTML documents; executable code and arbitrary files are never included.
$ysGatewayConfig = \YourShield\RuntimeConfig::fromFile((string) constant('YS_RELEASE_ROOT') . '/config.php');
$ysGatewayRoot = realpath($ysGatewayConfig->getString('application_root', $ysGatewayConfig->getString('public_root')));
$ysGatewayMount = rtrim($ysGatewayConfig->getString('mount_path'), '/');
$ysGatewayPath = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
$ysGatewayPath = is_string($ysGatewayPath) ? rawurldecode($ysGatewayPath) : '';
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
    header('Allow: GET, HEAD');
    http_response_code(405);
    exit;
}
if ($ysGatewayRoot === false || $ysGatewayPath === '' || str_contains($ysGatewayPath, "\0")
    || str_contains($ysGatewayPath, '\\')
    || ($ysGatewayMount !== '' && $ysGatewayPath !== $ysGatewayMount
        && !str_starts_with($ysGatewayPath, $ysGatewayMount . '/'))
) {
    http_response_code(404);
    exit;
}
$ysGatewayRelative = ltrim(substr($ysGatewayPath, strlen($ysGatewayMount)), '/');
foreach (explode('/', $ysGatewayRelative) as $ysGatewayPart) {
    if ($ysGatewayPart === '..' || str_starts_with($ysGatewayPart, '.')) {
        http_response_code(404);
        exit;
    }
}
$ysGatewayFile = $ysGatewayRoot . '/' . $ysGatewayRelative;
if (is_dir($ysGatewayFile)) {
    $ysGatewayFile = rtrim($ysGatewayFile, '/') . (is_file(rtrim($ysGatewayFile, '/') . '/index.html') ? '/index.html' : '/index.htm');
}
$ysGatewayResolved = realpath($ysGatewayFile);
if ($ysGatewayResolved === false || !is_file($ysGatewayResolved)
    || !\YourShield\Utils::pathIsInside($ysGatewayRoot, $ysGatewayResolved)
    || !in_array(strtolower(pathinfo($ysGatewayResolved, PATHINFO_EXTENSION)), ['html', 'htm'], true)
) {
    http_response_code(404);
    exit;
}
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
    readfile($ysGatewayResolved);
}
