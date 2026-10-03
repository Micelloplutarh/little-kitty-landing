<?php
declare(strict_types=1);

namespace YourShield;

final class ModuleRouter
{
    private RuntimeConfig $config;
    private CacheBackend $cache;
    private RateLimiter $rateLimiter;
    private CloudClient $cloudClient;
    private MetricsBuffer $metrics;
    private array $trustedProxyCfg;

    public function __construct(
        RuntimeConfig $config,
        CacheBackend $cache,
        RateLimiter $rateLimiter,
        CloudClient $cloudClient,
        MetricsBuffer $metrics
    ) {
        $this->config = $config;
        $this->cache = $cache;
        $this->rateLimiter = $rateLimiter;
        $this->cloudClient = $cloudClient;
        $this->metrics = $metrics;
        $this->trustedProxyCfg = $config->getArray('trusted_proxy');
    }

    public function handle(string $requestPath, array $routeBundle, array $server): bool
    {
        $basePath = $this->config->getString('base_path');
        if (!Utils::isPathUnderBase($requestPath, $basePath)) {
            return false;
        }

        $relativePath = Utils::relativeToBase($requestPath, $basePath);

        if ($relativePath === '/health') {
            $this->sendJson(200, [
                'ok' => true,
                'ts' => time(),
                'module' => 'yourshield',
            ]);
            return true;
        }

        if ($relativePath === '/debug/self-test') {
            if (!$this->config->getBool('debug', false)) {
                $this->uniformError(404);
                return true;
            }

            $this->sendJson(200, [
                'ok' => true,
                'debug' => true,
                'base_path' => $basePath,
                'route_bundle' => $routeBundle,
                'ip' => $this->clientIp($server),
            ]);
            return true;
        }

        if ($this->matchesRoute($relativePath, $routeBundle, 'challenge_path')) {
            $this->handleChallenge($routeBundle, $server);
            return true;
        }

        if ($this->matchesRoute($relativePath, $routeBundle, 'solve_path')) {
            $this->handleSolve($routeBundle, $server);
            return true;
        }

        if ($this->matchesRoute($relativePath, $routeBundle, 'session_ingest_path')) {
            $this->handleIngest('session', $server);
            return true;
        }

        if ($this->matchesRoute($relativePath, $routeBundle, 'metrics_ingest_path')) {
            $this->handleIngest('metrics', $server);
            return true;
        }

        $this->uniformError(404);
        return true;
    }

    private function handleChallenge(array $routeBundle, array $server): void
    {
        if (!$this->consumeRouteLimit('challenge', $server)) {
            $this->metrics->recordRateLimit('challenge');
            $this->uniformError(429);
            return;
        }

        $method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET'));
        if ($method !== 'GET' && $method !== 'HEAD') {
            $this->uniformError(404);
            return;
        }

        $rid = trim((string) ($_GET['rid'] ?? ''));
        if ($rid === '') {
            $this->uniformError(404);
            return;
        }

        $state = $this->cache->get($this->ridKey($rid), null);
        if (!is_array($state)) {
            $this->uniformError(404);
            return;
        }

        $fp = (string) ($state['fingerprint'] ?? '');
        if ($fp !== '' && !hash_equals($fp, Utils::fingerprint($server, $this->trustedProxyCfg))) {
            $this->uniformError(404);
            return;
        }

        $payload = [
            'api_ver' => $this->config->getString('api_ver', '1'),
            'site_key' => $this->config->getString('site_key'),
            'rid' => $rid,
            'client_ip' => $this->clientIp($server),
            'host' => $server['HTTP_HOST'] ?? null,
            'route_bundle_id' => $state['route_bundle_id'] ?? ($routeBundle['current']['id'] ?? null),
        ];

        $response = $this->cloudClient->challengeHtml($payload);
        if (!$response['ok']) {
            $this->metrics->recordCloudError('challenge_html');
            if ((int) ($response['status'] ?? 0) === 429) {
                header('Retry-After: ' . (int) ($response['retry_after'] ?? 60));
                $this->sendJson(429, ['ok' => false, 'error' => 'rate_limited']);
                return;
            }
            if (
                CloudClient::usesConfiguredFailMode($response)
                && $this->shouldFailOpen((string) ($state['original_path'] ?? '/'))
            ) {
                $fp = trim((string) ($state['fingerprint'] ?? ''));
                if ($fp !== '') {
                    $this->cache->set(
                        $this->failOpenKey($fp, (string) ($state['original_path'] ?? '/')),
                        1,
                        60
                    );
                }
                $this->cache->delete($this->ridKey($rid));
                $this->redirect($this->returnTarget($state), 302);
                return;
            }

            $this->sendText(503, 'Service unavailable');
            return;
        }

        $data = is_array($response['data']) ? $response['data'] : [];
        $html = is_string($data['html'] ?? null)
            ? (string) $data['html']
            : $this->fallbackChallengeHtml($state, $data, $routeBundle);

        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        header('Referrer-Policy: same-origin');
        header('Content-Type: text/html; charset=utf-8');
        http_response_code(200);
        echo $html;
    }

    private function handleSolve(array $routeBundle, array $server): void
    {
        if (!$this->consumeRouteLimit('solve', $server)) {
            $this->metrics->recordRateLimit('solve');
            $this->uniformError(429);
            return;
        }

        $method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'POST'));
        if ($method !== 'POST') {
            $this->uniformError(404);
            return;
        }

        $contentType = strtolower((string) ($server['CONTENT_TYPE'] ?? ''));
        if (!str_contains($contentType, 'application/json')) {
            $this->uniformError(404);
            return;
        }

        $origin = (string) ($server['HTTP_ORIGIN'] ?? '');
        if ($origin !== '' && !Utils::sameOrigin($server, $origin, $this->trustedProxyCfg)) {
            $this->uniformError(404);
            return;
        }

        $referer = (string) ($server['HTTP_REFERER'] ?? '');
        if ($referer !== '' && !Utils::sameOrigin($server, $referer, $this->trustedProxyCfg)) {
            $this->uniformError(404);
            return;
        }
        if ($origin === '' && $referer === '') {
            $this->uniformError(404);
            return;
        }

        $raw = Utils::readRequestBody($this->config->getInt('body_limit_bytes', 32768), $server);
        if ($raw === null) {
            $this->uniformError(404);
            return;
        }

        $json = json_decode($raw, true);
        if (!is_array($json)) {
            $this->uniformError(404);
            return;
        }

        $rid = trim((string) ($json['rid'] ?? ''));
        $csrf = trim((string) ($json['csrf'] ?? ''));
        if ($rid === '' || $csrf === '') {
            $this->uniformError(404);
            return;
        }

        $ridKey = $this->ridKey($rid);
        $state = $this->cache->get($ridKey, null);
        if (!is_array($state)) {
            $this->uniformError(404);
            return;
        }

        $fp = (string) ($state['fingerprint'] ?? '');
        if ($fp !== '' && !hash_equals($fp, Utils::fingerprint($server, $this->trustedProxyCfg))) {
            $this->uniformError(404);
            return;
        }

        $maxTries = max(1, $this->config->getInt('rid_max_tries', 5));
        $tries = (int) ($state['tries'] ?? 0) + 1;
        $state['tries'] = $tries;
        $ttlRemaining = max(1, ((int) ($state['created_at'] ?? time()) + $this->config->getInt('rid_ttl_sec', 180)) - time());
        $this->cache->set($ridKey, $state, $ttlRemaining);

        if ($tries > $maxTries || !hash_equals((string) ($state['csrf'] ?? ''), $csrf)) {
            if ($tries > $maxTries) {
                $this->cache->delete($ridKey);
            }
            $this->uniformError($tries > $maxTries ? 429 : 404);
            return;
        }

        $payload = [
            'api_ver' => $this->config->getString('api_ver', '1'),
            'site_key' => $this->config->getString('site_key'),
            'rid' => $rid,
            'csrf' => $csrf,
            'fp_payload' => $json['fp_payload'] ?? [],
            'timings' => $json['timings'] ?? [],
            'host' => $server['HTTP_HOST'] ?? null,
            'browser_context' => [
                'host' => $server['HTTP_HOST'] ?? null,
                'origin' => $origin !== '' ? $origin : null,
                'referer' => $referer !== '' ? $referer : null,
            ],
            'client_ip' => $this->clientIp($server),
            'ua' => trim((string) ($server['HTTP_USER_AGENT'] ?? '')),
            'route_bundle_id' => $state['route_bundle_id'] ?? ($routeBundle['current']['id'] ?? null),
        ];
        if (isset($json['pow_solution']) && is_scalar($json['pow_solution'])) {
            $powSolution = trim((string) $json['pow_solution']);
            if ($powSolution !== '') {
                $payload['pow_solution'] = $powSolution;
            }
        }

        $response = $this->cloudClient->solve($payload);
        if (!$response['ok']) {
            $this->metrics->recordCloudError('solve');
            if ((int) ($response['status'] ?? 0) === 429) {
                header('Retry-After: ' . (int) ($response['retry_after'] ?? 60));
                $this->sendJson(429, ['ok' => false, 'error' => 'rate_limited']);
                return;
            }
            if (
                CloudClient::usesConfiguredFailMode($response)
                && $this->shouldFailOpen((string) ($state['original_path'] ?? '/'))
            ) {
                $fp = trim((string) ($state['fingerprint'] ?? ''));
                if ($fp !== '') {
                    $this->cache->set(
                        $this->failOpenKey($fp, (string) ($state['original_path'] ?? '/')),
                        1,
                        60
                    );
                }
                $this->cache->delete($ridKey);
                $this->sendJson(200, [
                    'ok' => true,
                    'decision' => 'allow',
                    'next' => $this->returnTarget($state),
                ]);
                return;
            }

            $this->sendJson(503, ['ok' => false]);
            return;
        }

        $data = is_array($response['data']) ? $response['data'] : [];
        $decisionRaw = $data['decision'] ?? null;
        $decision = is_string($decisionRaw) ? strtolower(trim($decisionRaw)) : '';
        $fp = trim((string) ($state['fingerprint'] ?? ''));

        $sid = trim((string) ($data['sid'] ?? ''));
        if ($sid !== '') {
            if ($fp !== '') {
                $this->cache->set($this->fpSidKey($fp), $sid, 3600);
            }
        }

        if ($decision === 'whitepage') {
            $this->cache->delete($ridKey);
            $whitepageHtml = is_string($data['whitepage_page']['html'] ?? null)
                ? trim((string) $data['whitepage_page']['html'])
                : '';
            if ($whitepageHtml === '') {
                $whitepageHtml = '<!doctype html><html><body><h1>Please continue later</h1></body></html>';
            }

            $this->sendJson(200, [
                'ok' => true,
                'decision' => 'whitepage',
                'whitepage_page' => [
                    'html' => $whitepageHtml,
                ],
                'sid' => $sid !== '' ? $sid : null,
                'risk_profile' => $data['risk_profile'] ?? null,
            ]);
            return;
        }

        if ($decision === 'block') {
            $this->cache->delete($ridKey);

            $whitepageOverride = BotBlockPageResolver::resolve(
                $this->config,
                'solve|' . $fp . '|' . $rid
            );
            if ($whitepageOverride !== null) {
                $this->sendJson(200, [
                    'ok' => true,
                    'decision' => 'whitepage',
                    'whitepage_page' => [
                        'html' => (string) ($whitepageOverride['html'] ?? ''),
                    ],
                    'sid' => $sid !== '' ? $sid : null,
                    'risk_profile' => $data['risk_profile'] ?? null,
                ]);
                return;
            }

            $blockHtml = is_string($data['block_page']['html'] ?? null)
                ? trim((string) $data['block_page']['html'])
                : '';
            if ($blockHtml === '') {
                $blockHtml = '<!doctype html><html><body><h1>Access denied</h1></body></html>';
            }

            $this->sendJson(200, [
                'ok' => true,
                'decision' => 'block',
                'block_page' => [
                    'html' => $blockHtml,
                ],
                'sid' => $sid !== '' ? $sid : null,
                'risk_profile' => $data['risk_profile'] ?? null,
            ]);
            return;
        }

        if ($decision !== 'allow') {
            $this->metrics->recordCloudError('solve_contract');
            if ($this->shouldFailOpen((string) ($state['original_path'] ?? '/'))) {
                if ($fp !== '') {
                    $this->cache->set(
                        $this->failOpenKey($fp, (string) ($state['original_path'] ?? '/')),
                        1,
                        60
                    );
                }
                $this->cache->delete($ridKey);
                $this->sendJson(200, [
                    'ok' => true,
                    'decision' => 'allow',
                    'next' => $this->returnTarget($state),
                ]);
                return;
            }
            $this->sendJson(503, ['ok' => false]);
            return;
        }

        $next = $this->returnTarget($state);
        BrowserProof::store($this->config, $this->cache, $server, $data);
        if ($fp !== '' && ($state['browser_navigation'] ?? true) === true) {
            // Resume only the solved navigation, including legacy cloud responses with positive TTL.
            $this->cache->set('ys:continue:' . $fp . ':' . hash('sha256', $next), (string) $state['rid'], 120);
        }

        $this->cache->delete($ridKey);
        $this->sendJson(200, [
            'ok' => true,
            'decision' => 'allow',
            'next' => $next,
            'sid' => $sid !== '' ? $sid : null,
            'allow_ttl' => 0,
            'risk_profile' => $data['risk_profile'] ?? null,
        ]);
    }

    private function handleIngest(string $kind, array $server): void
    {
        if (!$this->consumeRouteLimit('ingest', $server)) {
            $this->metrics->recordRateLimit('ingest');
            $this->uniformError(429);
            return;
        }

        $method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'POST'));
        if ($method !== 'POST') {
            $this->uniformError(404);
            return;
        }

        $contentType = strtolower((string) ($server['CONTENT_TYPE'] ?? ''));
        if (!str_contains($contentType, 'application/json')) {
            $this->uniformError(404);
            return;
        }

        $origin = (string) ($server['HTTP_ORIGIN'] ?? '');
        $referer = (string) ($server['HTTP_REFERER'] ?? '');
        $hasSameOriginEvidence = false;
        if ($origin !== '') {
            if (!Utils::sameOrigin($server, $origin, $this->trustedProxyCfg)) {
                $this->uniformError(404);
                return;
            }
            $hasSameOriginEvidence = true;
        }
        if ($referer !== '') {
            if (!Utils::sameOrigin($server, $referer, $this->trustedProxyCfg)) {
                $this->uniformError(404);
                return;
            }
            $hasSameOriginEvidence = true;
        }
        if (!$hasSameOriginEvidence) {
            $this->uniformError(404);
            return;
        }

        $raw = Utils::readRequestBody($this->config->getInt('body_limit_bytes', 32768), $server);
        if ($raw === null) {
            $this->uniformError(404);
            return;
        }

        $json = json_decode($raw, true);
        if (!is_array($json)) {
            $this->uniformError(404);
            return;
        }

        $payload = [
            'api_ver' => $this->config->getString('api_ver', '1'),
            'site_key' => $this->config->getString('site_key'),
            'host' => $server['HTTP_HOST'] ?? null,
            'client_ip' => $this->clientIp($server),
            'payload' => $json,
        ];

        $response = $kind === 'session'
            ? $this->cloudClient->sessionIngest($payload)
            : $this->cloudClient->metricsIngest($payload);

        if (!$response['ok']) {
            $this->metrics->recordCloudError($kind . '_ingest');
            $this->sendJson(202, ['ok' => false]);
            return;
        }

        http_response_code(204);
    }

    private function fallbackChallengeHtml(array $state, array $data, array $routeBundle): string
    {
        $basePath = $this->config->getString('base_path');
        $requestedBundleId = is_string($data['bundle_id'] ?? null) ? trim($data['bundle_id']) : '';
        $bundleId = $this->resolveChallengeBundleId($requestedBundleId);
        $assetPath = rtrim($basePath, '/') . '/a/' . rawurlencode($bundleId) . '/challenge.js';
        $solvePath = $this->routePath($routeBundle, 'solve_path', true);
        $solveUrl = Utils::joinBaseAndRoute($basePath, $solvePath);

        $inline = [
            'rid' => (string) ($state['rid'] ?? ''),
            'csrf' => (string) ($state['csrf'] ?? ''),
            'solve_url' => $solveUrl,
            'bundle_id' => $bundleId,
            'next_url' => $this->returnTarget($state),
        ];

        $json = json_encode($inline, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        if (!is_string($json)) {
            $json = '{}';
        }

        // Inject PoW challenge params if provided by the backend
        $powScript = '';
        $powNonce = is_string($data['pow_nonce'] ?? null) ? $data['pow_nonce'] : '';
        $powDifficulty = is_int($data['pow_difficulty'] ?? null) ? $data['pow_difficulty'] : 0;
        if ($powNonce !== '' && $powDifficulty > 0) {
            $powJson = json_encode(
                ['nonce' => $powNonce, 'difficulty' => $powDifficulty],
                JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
            );
            $powScript = '<script>window.__POW=' . ($powJson ?: '{}') . ';</script>';
        }

        return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>Verification required</title>'
            . '<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f8fafc;color:#0f172a;font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.ys-wrap{width:min(420px,calc(100vw - 32px));padding:24px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;box-shadow:0 12px 30px rgba(15,23,42,.12)}.ys-title{margin:0 0 8px;font-size:20px;line-height:1.25}.ys-copy{margin:0;color:#475569}.ys-noscript{margin-top:16px;color:#991b1b}</style>'
            . '</head><body><main class="ys-wrap" aria-live="polite">'
            . '<h1 class="ys-title">Verification required</h1>'
            . '<div id="ys-challenge-root" class="ys-copy">Checking your browser...</div>'
            . '<noscript><p class="ys-noscript">JavaScript is required to complete this verification.</p></noscript>'
            . '</main>'
            . '<script>window.__YS=' . $json . ';</script>'
            . $powScript
            . '<script src="' . htmlspecialchars($assetPath, ENT_QUOTES, 'UTF-8') . '" defer></script>'
            . '</body></html>';
    }

    private function resolveChallengeBundleId(string $requestedBundleId): string
    {
        $basePath = trim($this->config->getString('base_path'), '/');
        $publicRoot = rtrim($this->config->getString('public_root', dirname(__DIR__, 2) . '/public'), '/\\');
        $assetRoot = $publicRoot . ($basePath === '' ? '' : '/' . $basePath) . '/a';

        if ($this->challengeAssetExists($assetRoot, $requestedBundleId)) {
            return $requestedBundleId;
        }

        $currentTarget = AssetUpdater::activeBundleId($assetRoot);
        if (is_string($currentTarget) && $this->challengeAssetExists($assetRoot, $currentTarget)) {
            return $currentTarget;
        }

        return preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}[a-zA-Z0-9]\z/', $requestedBundleId) === 1
            ? $requestedBundleId
            : 'current';
    }

    private function challengeAssetExists(string $assetRoot, string $bundleId): bool
    {
        if (preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}[a-zA-Z0-9]\z/', $bundleId) !== 1) {
            return false;
        }

        $bundlePath = $assetRoot . '/' . $bundleId;
        $filePath = $bundlePath . '/challenge.js';
        if (is_link($bundlePath) || is_link($filePath)) {
            return false;
        }

        $root = realpath($assetRoot);
        $bundle = realpath($bundlePath);
        $file = realpath($filePath);
        return is_string($root)
            && is_string($bundle)
            && is_string($file)
            && dirname($bundle) === $root
            && dirname($file) === $bundle
            && is_file($file);
    }

    private function consumeRouteLimit(string $bucket, array $server): bool
    {
        $ip = $this->clientIp($server);
        $limits = $this->config->getArray('rate_limits');

        $base = $limits['base'] ?? ['rate_per_sec' => 2.0, 'burst' => 120];
        $baseOk = $this->rateLimiter->consume(
            'base:' . $ip,
            (float) ($base['rate_per_sec'] ?? 2.0),
            (int) ($base['burst'] ?? 120)
        );
        if (!$baseOk) {
            return false;
        }

        $cfg = $limits[$bucket] ?? ['rate_per_sec' => 1.0, 'burst' => 60];
        return $this->rateLimiter->consume(
            $bucket . ':' . $ip,
            (float) ($cfg['rate_per_sec'] ?? 1.0),
            (int) ($cfg['burst'] ?? 60)
        );
    }

    private function matchesRoute(string $relativePath, array $bundle, string $routeKey): bool
    {
        foreach (['current', 'prev'] as $slot) {
            $candidate = $bundle[$slot][$routeKey] ?? null;
            if (!is_string($candidate) || $candidate === '') {
                continue;
            }
            $normalized = Utils::normalizeRoutePath($candidate, $this->config->getString('base_path'));
            if ($relativePath === $normalized) {
                return true;
            }
        }

        return false;
    }

    private function routePath(array $bundle, string $routeKey, bool $preferCurrent = true): string
    {
        $slots = $preferCurrent ? ['current', 'prev'] : ['prev', 'current'];
        foreach ($slots as $slot) {
            $candidate = $bundle[$slot][$routeKey] ?? null;
            if (is_string($candidate) && $candidate !== '') {
                return Utils::normalizeRoutePath($candidate, $this->config->getString('base_path'));
            }
        }
        return '/';
    }

    private function shouldFailOpen(string $path): bool
    {
        return $this->config->shouldFailOpen($path, $this->cache);
    }

    private function failOpenKey(string $fingerprint, string $path): string
    {
        return 'ys:fail_open:' . $fingerprint . ':' . hash('sha256', $path);
    }

    private function ridKey(string $rid): string
    {
        return 'ys:rid:' . $rid;
    }

    private function fpSidKey(string $fingerprint): string
    {
        return 'ys:fp_sid:' . $fingerprint;
    }

    private function returnTarget(array $state): string
    {
        $target = ($state['browser_navigation'] ?? true) === true
            ? ($state['original_url'] ?? '/') : ($state['return_url'] ?? '/');
        return Utils::requestTarget(['REQUEST_URI' => (string) $target]);
    }

    private function uniformError(int $status): void
    {
        $status = $status === 429 ? 429 : 404;
        if ($status === 429) header('Retry-After: 1');
        $this->sendJson($status, ['ok' => false]);
    }

    private function sendText(int $status, string $body): void
    {
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        echo $body;
    }

    private function sendJson(int $status, array $payload): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
        echo is_string($encoded) ? $encoded : '{"ok":false}';
    }

    private function redirect(string $url, int $status = 302): void
    {
        http_response_code($status);
        header('Cache-Control: no-store');
        header('Location: ' . Utils::requestTarget(['REQUEST_URI' => $url]), true, $status);
    }

    private function clientIp(array $server): string
    {
        return Utils::clientIp($server, $this->trustedProxyCfg);
    }
}
