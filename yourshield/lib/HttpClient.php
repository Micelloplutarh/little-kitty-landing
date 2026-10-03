<?php
declare(strict_types=1);

namespace YourShield;

final class HttpClient
{
    public function request(
        string $method,
        string $url,
        array $headers = [],
        ?string $body = null,
        int $connectTimeoutMs = 200,
        int $timeoutMs = 800,
        int $maxResponseBytes = 0
    ): array {
        $ch = curl_init($url);
        if ($ch === false) {
            return [
                'status' => 0,
                'headers' => [],
                'body' => '',
                'error' => 'curl_init_failed',
                'latency_ms' => 0,
            ];
        }

        $responseHeaders = [];
        $start = microtime(true);

        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT_MS => max(1, $connectTimeoutMs),
            CURLOPT_TIMEOUT_MS => max(1, $timeoutMs),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $headerLine) use (&$responseHeaders): int {
                $len = strlen($headerLine);
                $parts = explode(':', $headerLine, 2);
                if (count($parts) === 2) {
                    $name = strtolower(trim($parts[0]));
                    $value = trim($parts[1]);
                    $responseHeaders[$name][] = $value;
                }
                return $len;
            },
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $boundedBody = '';
        if ($maxResponseBytes > 0) {
            curl_setopt($ch, CURLOPT_WRITEFUNCTION, static function ($curl, string $chunk) use (&$boundedBody, $maxResponseBytes): int {
                if (strlen($boundedBody) + strlen($chunk) > $maxResponseBytes) {
                    return 0;
                }
                $boundedBody .= $chunk;
                return strlen($chunk);
            });
        }

        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errorCode = curl_errno($ch);
        $error = $errorCode !== 0 ? curl_error($ch) : null;
        $latency = (int) round((microtime(true) - $start) * 1000);
        curl_close($ch);

        return [
            'status' => $status,
            'headers' => $responseHeaders,
            'body' => $maxResponseBytes > 0 ? ($error === null ? $boundedBody : '') : (is_string($raw) ? $raw : ''),
            'error' => $error,
            'error_code' => $errorCode,
            'latency_ms' => $latency,
        ];
    }
}
