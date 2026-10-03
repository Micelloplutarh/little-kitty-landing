<?php
declare(strict_types=1);

namespace YourShield;

final class CloudClient
{
    private RuntimeConfig $config;
    private HttpClient $httpClient;
    private HmacSigner $signer;

    public function __construct(RuntimeConfig $config, HttpClient $httpClient, HmacSigner $signer)
    {
        $this->config = $config;
        $this->httpClient = $httpClient;
        $this->signer = $signer;
    }

    public function check(array $payload): array
    {
        return $this->signedPost('check', $payload);
    }

    public function handshake(array $payload): array
    {
        return $this->signedPost('site_handshake', $payload);
    }

    public function challengeHtml(array $payload): array
    {
        return $this->signedPost('challenge_html', $payload);
    }

    public function solve(array $payload): array
    {
        return $this->signedPost('challenge_solve', $payload);
    }

    public function metricsIngest(array $payload): array
    {
        return $this->signedPost('metrics_ingest', $payload);
    }

    public function sessionIngest(array $payload): array
    {
        return $this->signedPost('session_ingest', $payload);
    }

    public function assetsManifest(array $payload): array
    {
        return $this->signedPost('assets_manifest', $payload);
    }

    public function assetsBundle(array $payload): array
    {
        return $this->signedPost('assets_bundle', $payload);
    }

    public function moduleManifest(array $payload): array
    {
        return $this->signedPost('module_manifest', $payload);
    }

    public function moduleFile(array $payload): array
    {
        return $this->signedPost('module_file', $payload);
    }

    public static function usesConfiguredFailMode(array $response): bool
    {
        $status = (int) ($response['status'] ?? 0);
        if (in_array(($response['data']['error'] ?? ''), ['browser_proof_unavailable', 'cloud_quota_unavailable'], true)) {
            return false;
        }
        return $status === 0 || $status === 408 || $status >= 500;
    }

    private function signedPost(string $pathKey, array $payload): array
    {
        $paths = $this->config->getArray('cloud_paths');
        $endpoint = $paths[$pathKey] ?? null;
        if (!is_string($endpoint) || $endpoint === '') {
            return [
                'ok' => false,
                'status' => 0,
                'data' => [],
                'error' => 'missing_cloud_path_' . $pathKey,
                'latency_ms' => 0,
            ];
        }

        $baseUrl = rtrim($this->config->getString('cloud_base_url'), '/');
        $urlPolicy = $this->config->getArray('cloud_url_policy');
        $urlIssue = Utils::validateCloudBaseUrl($baseUrl, $urlPolicy);
        if ($urlIssue !== null) {
            return [
                'ok' => false,
                'status' => 0,
                'data' => [],
                'error' => $urlIssue,
                'latency_ms' => 0,
            ];
        }

        $url = $baseUrl . '/' . ltrim($endpoint, '/');
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($body)) {
            return [
                'ok' => false,
                'status' => 0,
                'data' => [],
                'error' => 'json_encode_failed',
                'latency_ms' => 0,
            ];
        }

        $path = parse_url($url, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            $path = '/';
        }

        $headers = [
            'Content-Type: application/json',
            'Accept: application/json',
        ];
        $headers = array_merge(
            $headers,
            $this->signer->buildHeaders(
                'POST',
                $path,
                $body,
                $this->config->getString('site_key'),
                $this->config->getString('secret'),
                $this->config->getString('api_ver', '1')
            )
        );

        $timeouts = $this->config->getArray('timeouts');
        $response = $this->httpClient->request(
            'POST',
            $url,
            $headers,
            $body,
            (int) ($timeouts['connect_ms'] ?? 200),
            (int) ($timeouts['total_ms'] ?? 800)
        );

        $decoded = json_decode((string) $response['body'], true);
        if (!is_array($decoded)) {
            $decoded = [];
        }

        $status = (int) ($response['status'] ?? 0);
        return [
            'ok' => $status >= 200 && $status < 300 && ($response['error'] ?? null) === null,
            'status' => $status,
            'data' => $decoded,
            'error' => $response['error'] ?? null,
            'error_code' => (int) ($response['error_code'] ?? 0),
            'latency_ms' => (int) ($response['latency_ms'] ?? 0),
            'raw_body' => (string) ($response['body'] ?? ''),
            'retry_after' => min(86400, max(1, (int) ($response['headers']['retry-after'][0] ?? 60))),
        ];
    }
}
