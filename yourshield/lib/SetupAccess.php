<?php
declare(strict_types=1);

namespace YourShield;

use DomainException;
use RuntimeException;

/** Package-bound setup access. Runtime credentials never enter the browser session. */
final class SetupAccess
{
    private RuntimeConfig $config;
    private string $moduleRoot;

    public function __construct(RuntimeConfig $config)
    {
        $this->config = $config;
        $this->moduleRoot = defined('YS_MODULE_ROOT')
            ? rtrim((string) constant('YS_MODULE_ROOT'), '/\\')
            : rtrim($config->getString('project_root'), '/\\') . '/yourshield';
    }

    public function available(): bool
    {
        $installation = $this->config->getArray('installation');
        return !file_exists($this->moduleRoot . '/.setup-complete.php')
            && !is_link($this->moduleRoot . '/.setup-complete.php')
            && ($installation['status'] ?? '') !== 'active'
            && ($this->config->getString('installed_at') === '' || ($installation['status'] ?? '') === 'needs_action')
            && $this->metadata() !== [];
    }

    public function isAuthorized(): bool
    {
        $metadata = $this->metadata();
        $authorized = $this->available() && $metadata !== []
            && is_string($_SESSION['ys_setup_ticket'] ?? null)
            && hash_equals($metadata['ticket_id'], $_SESSION['ys_setup_ticket']);
        if (!$authorized) { return false; }
        $claim = $this->cache()->get('claim:' . $metadata['ticket_id'], []);
        return is_array($claim) && ($claim['recovery_until'] ?? 0) > time();
    }

    public function authorize(string $code, string $host): array
    {
        $metadata = $this->metadata();
        $host = $this->host($host);
        if (!$this->available() || $metadata === [] || $host === ''
            || !$this->hostAllowed($host, $metadata['allowed_hosts'])) {
            throw new DomainException('setup_access_denied');
        }
        $cache = $this->cache();
        $attemptKey = 'attempts:' . $metadata['ticket_id'] . ':' . hash('sha256', (string) ($_SERVER['REMOTE_ADDR'] ?? 'cli'));
        $attempts = $cache->mutate($attemptKey, 300,
            static fn ($value): int => (int) $value + 1, 0);
        if ($attempts > 20 || strlen($code) !== 64
            || !hash_equals($metadata['code_hash'], hash('sha256', $code))) {
            throw new DomainException('setup_access_denied');
        }
        $key = 'claim:' . $metadata['ticket_id'];
        // add() elects one installation claim even when two setup requests race.
        $cache->add($key, ['claim_id' => bin2hex(random_bytes(16)),
            'claim_secret' => bin2hex(random_bytes(32)), 'host' => $host,
            'recovery_until' => min($metadata['expires_at'], time() + 7200)],
            max(1, $metadata['expires_at'] - time()));
        $claim = $cache->get($key);
        if (!is_array($claim) || ($claim['host'] ?? '') !== $host || ($claim['recovery_until'] ?? 0) <= time()) {
            throw new DomainException('setup_access_denied');
        }
        if (!is_array($claim['credentials'] ?? null)) {
            $data = $this->exchange($metadata, $claim, 'claim', $code);
            if (!is_string($data['site_key'] ?? null) || $data['site_key'] === ''
                || !is_string($data['secret'] ?? null) || strlen($data['secret']) < 16
                || ($data['site_host'] ?? '') !== $host) {
                throw new RuntimeException('setup_exchange_failed');
            }
            $claim['credentials'] = [
                'site_key' => $data['site_key'], 'secret' => $data['secret'],
                'site_host' => $host, 'cloud_url' => $metadata['cloud_url'],
            ];
            $cache->set($key, $claim, max(1, $metadata['expires_at'] - time()));
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
        $_SESSION['ys_setup_ticket'] = $metadata['ticket_id'];
        $cache->delete($attemptKey);
        return $claim['credentials'];
    }

    public function pendingCredentials(): array
    {
        if (!$this->isAuthorized()) {
            return [];
        }
        $metadata = $this->metadata();
        $claim = $this->cache()->get('claim:' . $metadata['ticket_id'], []);
        return ($claim['recovery_until'] ?? 0) > time() && is_array($claim['credentials'] ?? null) ? $claim['credentials'] : [];
    }

    public function complete(): bool
    {
        if (!$this->isAuthorized()) {
            throw new DomainException('setup_access_denied');
        }
        $metadata = $this->metadata();
        $claim = $this->cache()->get('claim:' . $metadata['ticket_id'], []);
        $path = $this->moduleRoot . '/.setup-complete.php';
        $handle = @fopen($path, 'x');
        if ($handle === false) {
            throw new RuntimeException('setup_lock_failed');
        }
        try {
            if (PHP_OS_FAMILY !== 'Windows' && !chmod($path, 0600)) {
                throw new RuntimeException('setup_lock_failed');
            }
            $content = '<?php http_response_code(404); exit;';
            if (fwrite($handle, $content) !== strlen($content) || !fflush($handle)) {
                throw new RuntimeException('setup_lock_failed');
            }
        } finally { fclose($handle); }
        unset($_SESSION['ys_setup_ticket']);
        try {
            $this->exchange($metadata, $claim, 'complete');
            return true;
        } catch (\Throwable $error) {
            return false;
        } finally {
            // The durable local lock remains even when the cloud completion response is lost.
            $this->cache()->delete('claim:' . $metadata['ticket_id']);
        }
    }

    private function metadata(): array
    {
        $path = $this->moduleRoot . '/setup.php';
        if (!is_file($path) || is_link($path) || Utils::ownershipIssue($path) !== null) {
            return [];
        }
        $data = require $path;
        if (!is_array($data) || !is_string($data['ticket_id'] ?? null)
            || !preg_match('/\A[a-f0-9]{32}\z/', $data['ticket_id'])
            || !is_string($data['code_hash'] ?? null)
            || !preg_match('/\A[a-f0-9]{64}\z/', $data['code_hash'])
            || !is_int($data['expires_at'] ?? null) || $data['expires_at'] <= time()
            || !is_string($data['exchange_url'] ?? null)) {
            return [];
        }
        $url = $data['exchange_url'];
        $suffix = '/v1/setup/exchange';
        if (!str_ends_with($url, $suffix)) {
            return [];
        }
        $base = substr($url, 0, -strlen($suffix));
        if (Utils::validateCloudBaseUrl($base, $this->config->getArray('cloud_url_policy')) !== null) {
            return [];
        }
        $hosts = $data['allowed_hosts'] ?? [$data['site_host'] ?? ''];
        if (!is_array($hosts) || $hosts === [] || count($hosts) > 100) {
            return [];
        }
        foreach ($hosts as $host) {
            if (!is_string($host)) {
                return [];
            }
            $suffix = str_starts_with($host, '*.') ? substr($host, 2) : $host;
            if ($suffix === '' || $this->host($suffix) !== $suffix) {
                return [];
            }
        }
        $data['allowed_hosts'] = $hosts;
        $data['cloud_url'] = $base;
        return $data;
    }

    private function cache(): FileCache
    {
        $moduleRoot = Utils::canonicalAbsolutePath($this->moduleRoot);
        if ($moduleRoot === null) { throw new RuntimeException('setup_storage_failed'); }
        // Installation can change runtime_dir before a staged setup is ready to complete.
        $path = rtrim(sys_get_temp_dir(), '/\\') . '/.yourshield-setup-' . hash('sha256', $moduleRoot);
        foreach ([$this->config->getString('public_root'), $this->config->getString('document_root'),
            (string) ($_SERVER['DOCUMENT_ROOT'] ?? '')] as $publicRoot) {
            if ($publicRoot !== '' && (Utils::pathIsInside($publicRoot, $path) || Utils::pathIsInside($path, $publicRoot))) {
                throw new RuntimeException('setup_storage_failed');
            }
        }
        return new FileCache($path);
    }

    private function host(string $host): string
    {
        if (!preg_match('/\A[a-z0-9.-]+(?::[0-9]{1,5})?\z/i', $host)) {
            return '';
        }
        return strtolower((string) parse_url('https://' . $host, PHP_URL_HOST));
    }

    private function hostAllowed(string $host, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (!str_starts_with($pattern, '*.')) {
                if ($host === $pattern) { return true; }
                continue;
            }
            // Match KEHR and cloud policy: a wildcard includes the apex and its subdomains.
            $suffix = substr($pattern, 2);
            if ($host === $suffix || str_ends_with($host, '.' . $suffix)) { return true; }
        }
        return false;
    }

    private function exchange(array $metadata, array $claim, string $action, string $code = ''): array
    {
        $body = json_encode(['ticket_id' => $metadata['ticket_id'], 'setup_code' => $code,
            'claim_id' => $claim['claim_id'], 'claim_secret' => $claim['claim_secret'],
            'host' => $claim['host'], 'action' => $action], JSON_THROW_ON_ERROR);
        $response = (new HttpClient())->request('POST', $metadata['exchange_url'],
            ['Content-Type: application/json', 'Accept: application/json'], $body, 1000, 5000);
        $data = strlen($response['body']) <= 8192 ? json_decode($response['body'], true) : null;
        if ($response['status'] !== 200 || $response['error'] !== null
            || !is_array($data) || ($data['ok'] ?? false) !== true) {
            throw new RuntimeException('setup_exchange_failed');
        }
        return $data;
    }
}
