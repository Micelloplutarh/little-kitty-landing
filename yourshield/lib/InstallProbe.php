<?php
declare(strict_types=1);

namespace YourShield;

/** Installer-only hook verification. The bearer token never reaches application code. */
final class InstallProbe
{
    public static function respond(RuntimeConfig $config, array $server): void
    {
        $state = $config->getArray('installation');
        $token = $server['HTTP_X_YOURSHIELD_INSTALL_PROBE'] ?? null;
        if (!is_string($token) || $token === ''
            || !is_string($state['probe_hash'] ?? null)
            || (int) ($state['probe_expires_at'] ?? 0) < time()
            || !hash_equals($state['probe_hash'], hash('sha256', $token))
        ) {
            return;
        }
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo json_encode([
            'yourshield_probe' => hash('sha256', $token),
            'script' => basename((string) ($server['SCRIPT_FILENAME'] ?? '')),
        ]);
        exit;
    }
}
