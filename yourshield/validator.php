<?php
declare(strict_types=1);

// Deliberately no runtime autoload: each request compiles exactly one isolated staged file.
header('Cache-Control: no-store');
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || (int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 4096
    || !is_file(__DIR__ . '/config.local.php') || is_link(__DIR__ . '/config.local.php')
) {
    http_response_code(404);
    exit;
}
if (DIRECTORY_SEPARATOR !== '\\') {
    $ysValidationUid = function_exists('posix_geteuid') ? posix_geteuid() : false;
    if ($ysValidationUid === false) {
        $ysValidationOwnerProbe = @tempnam(sys_get_temp_dir(), '.ys-validator-owner-');
        $ysValidationUid = is_string($ysValidationOwnerProbe) ? fileowner($ysValidationOwnerProbe) : false;
        if (is_string($ysValidationOwnerProbe)) {
            @unlink($ysValidationOwnerProbe);
        }
    }
    if (!is_int($ysValidationUid) || $ysValidationUid === 0 || fileowner(__DIR__ . '/config.local.php') !== $ysValidationUid) {
        http_response_code(404);
        exit;
    }
}
$ysValidationConfig = require __DIR__ . '/config.local.php';
$ysValidationToken = $_SERVER['HTTP_X_YOURSHIELD_VALIDATOR'] ?? '';
$ysValidationExpected = $ysValidationConfig['module_update']['validator_token'] ?? '';
if (!is_string($ysValidationToken) || !is_string($ysValidationExpected) || strlen($ysValidationExpected) < 32
    || !hash_equals($ysValidationExpected, $ysValidationToken)
) {
    http_response_code(404);
    exit;
}
$ysValidationRaw = file_get_contents('php://input', false, null, 0, 4097);
$ysValidationBody = is_string($ysValidationRaw) && strlen($ysValidationRaw) <= 4096 ? json_decode($ysValidationRaw, true) : null;
$ysValidationRelative = is_array($ysValidationBody) ? ($ysValidationBody['path'] ?? '') : '';
if (!is_string($ysValidationRelative)
    || !preg_match('~^\.module-releases/\.stage-[A-Za-z0-9]+/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.php$~D', $ysValidationRelative)
    || !function_exists('opcache_compile_file') || !function_exists('opcache_get_status')
    || opcache_get_status(false) === false
) {
    http_response_code(422);
    exit;
}
$ysValidationPath = __DIR__ . '/' . $ysValidationRelative;
$ysValidationCursor = __DIR__;
foreach (explode('/', $ysValidationRelative) as $ysValidationPart) {
    if ($ysValidationPart === '..' || $ysValidationPart === '.') {
        http_response_code(404);
        exit;
    }
    $ysValidationCursor .= '/' . $ysValidationPart;
    if (is_link($ysValidationCursor)) {
        http_response_code(404);
        exit;
    }
}
$ysValidationHash = is_file($ysValidationPath) ? hash_file('sha256', $ysValidationPath) : false;
if (!is_string($ysValidationHash) || !is_string($ysValidationBody['sha256'] ?? null)
    || !hash_equals($ysValidationHash, $ysValidationBody['sha256'])
) {
    http_response_code(409);
    exit;
}
// A fatal compiler error terminates only this validation request; no pointer is changed here.
@opcache_invalidate($ysValidationPath, true);
$ysValidationOk = @opcache_compile_file($ysValidationPath);
header('Content-Type: application/json');
http_response_code($ysValidationOk ? 200 : 422);
echo json_encode(['ok' => $ysValidationOk, 'sha256' => $ysValidationHash]);
