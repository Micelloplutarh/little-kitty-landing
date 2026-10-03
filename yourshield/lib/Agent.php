<?php
declare(strict_types=1);

namespace YourShield;

final class Agent
{
    private const ROUTE_BUNDLE_KEY = 'ys:route_bundle';
    private const POLICY_BUNDLE_KEY = 'ys:policy_bundle';
    private const ASSETS_AUTO_NEXT_KEY = 'ys:assets:auto_update:next_at';
    private const ASSETS_AUTO_LOCK_KEY = 'ys:assets:auto_update:tick_lock';
    private const MODULE_AUTO_NEXT_KEY = 'ys:module:auto_update:next_at';
    private const MODULE_AUTO_LOCK_KEY = 'ys:module:auto_update:tick_lock';

    private RuntimeConfig $config;
    private CacheBackend $cache;
    private RateLimiter $rateLimiter;
    private CloudClient $cloudClient;
    private MetricsBuffer $metrics;
    private ModuleRouter $router;
    private array $trustedProxyCfg;
    private array $bundleSignatureCfg;
    private ?\Closure $logger = null;
    private array $requestServer = [];

    public function __construct(RuntimeConfig $config)
    {
        $this->config = $config;
        $this->trustedProxyCfg = $config->getArray('trusted_proxy');
        $this->bundleSignatureCfg = $config->getArray('bundle_signature');
        $this->cache = CacheFactory::create($config);
        $this->rateLimiter = new RateLimiter($this->cache);

        $httpClient = new HttpClient();
        $signer = new HmacSigner();
        $this->cloudClient = new CloudClient($config, $httpClient, $signer);
        $this->metrics = new MetricsBuffer($this->cache, $this->cloudClient, $config);
        $this->router = new ModuleRouter(
            $config,
            $this->cache,
            $this->rateLimiter,
            $this->cloudClient,
            $this->metrics
        );
    }

    public function setLogger(?callable $logger): void
    {
        $this->logger = $logger !== null ? \Closure::fromCallable($logger) : null;
    }

    public function run(array $server): void
    {
        if (PHP_SAPI === 'cli') {
            return;
        }
        $this->requestServer = $server;
        if (Utils::requestTarget($server) !== (string) ($server['REQUEST_URI'] ?? '/')) {
            $this->sendApplicationDecision(400, 'block', 'Invalid request target', 'invalid_request_target');
            exit;
        }

        $browserEscape = BrowserEscape::stripMarker((string) ($server['REQUEST_URI'] ?? '/'));
        if ($browserEscape['target'] !== (string) ($server['REQUEST_URI'] ?? '/')) {
            $server['REQUEST_URI'] = $browserEscape['target'];
            $server['QUERY_STRING'] = (string) (parse_url($browserEscape['target'], PHP_URL_QUERY) ?? '');
            $_SERVER['REQUEST_URI'] = $server['REQUEST_URI'];
            $_SERVER['QUERY_STRING'] = $server['QUERY_STRING'];
            parse_str($server['QUERY_STRING'], $cleanQuery);
            if (array_key_exists(BrowserEscape::MARKER, $cleanQuery)) {
                $_GET[BrowserEscape::MARKER] = $cleanQuery[BrowserEscape::MARKER];
            } else {
                unset($_GET[BrowserEscape::MARKER]);
            }
            BrowserEscape::restoreRequestMarker((string) (ini_get('request_order') ?: ini_get('variables_order')));
            $this->requestServer = $server;
        }
        if ($browserEscape['skip'] && Utils::isDocumentNavigation($server)) {
            BrowserEscape::setCookie(BrowserEscape::SKIP_COOKIE, $server, $this->trustedProxyCfg);
        }

        $requestPath = Utils::normalizePath((string) ($server['REQUEST_URI'] ?? '/'));
        $basePath = $this->config->getString('base_path');

        $routeBundle = $this->getRouteBundle();
        if ($this->router->handle($requestPath, $routeBundle, $server)) {
            $this->metrics->maybeFlush();
            exit;
        }

        if ($this->isExcludedPath($requestPath)) {
            return;
        }

        $clientIp = $this->clientIp($server);
        $fingerprint = Utils::fingerprint($server, $this->trustedProxyCfg);
        $sid = (string) $this->cache->get($this->fpSidKey($fingerprint), '');

        if (!$this->consumeCheckRateLimit($server)) {
            $this->metrics->recordRateLimit('check');
            header('Retry-After: 1');
            $this->sendApplicationDecision(429, 'block', 'Too many requests', 'rate_limited');
            exit;
        }

        $this->maybeTriggerAutoAssetsUpdate($server);
        $this->maybeTriggerAutoModuleUpdate($server);

        $continued = $this->consumeContinuation($fingerprint, $server);
        if ($continued) {
            header('Cache-Control: private, no-store');
        }
        if ($continued
            || ($this->shouldFailOpen($requestPath)
                && $this->cache->get($this->failOpenKey($fingerprint, $requestPath), null) !== null)
        ) {
            $this->metrics->recordCacheHit('allow');
            $this->metrics->recordDecision('allow');
            if ($sid !== '') {
                $this->metrics->recordSessionDecision($sid, 'allow', $requestPath);
            }
            $this->metrics->maybeFlush();
            return;
        }

        $payload = [
            'api_ver' => $this->config->getString('api_ver', '1'),
            'site_key' => $this->config->getString('site_key'),
            'module_version' => $this->config->getString('module_version', '1.1.4'),
            'host' => $server['HTTP_HOST'] ?? null,
            'method' => strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')),
            'path' => Utils::requestTarget($server),
            'ua' => trim((string) ($server['HTTP_USER_AGENT'] ?? '')),
            'referer' => (string) ($server['HTTP_REFERER'] ?? ''),
            'client_ip' => $clientIp,
            'sid' => $sid !== '' ? $sid : null,
            'fp_hint' => substr($fingerprint, 0, 24),
            'route_bundle_id' => $routeBundle['current']['id'] ?? null,
            'forwarded_headers' => self::collectForwardedHeaders($server),
            'browser_navigation' => Utils::isDocumentNavigation($server),
            'browser_proof' => BrowserProof::read($this->config, $this->cache),
            'browser_proof_version' => ($this->config->getArray('browser_proof')['enabled'] ?? true) === true ? 1 : 0,
            'browser_escape_version' => 1,
            'browser_escape_checked' => ($_COOKIE[BrowserEscape::CHECKED_COOKIE] ?? null) === '1',
            'browser_escape_skip' => $browserEscape['skip'] || ($_COOKIE[BrowserEscape::SKIP_COOKIE] ?? null) === '1',
        ];

        $response = $this->cloudClient->check($payload);
        $latencyBucket = $this->latencyBucket((int) ($response['latency_ms'] ?? 0));
        $this->metrics->recordLatency($latencyBucket);

        if (!$response['ok']) {
            $this->metrics->recordCloudError('check');
            if ((int) ($response['status'] ?? 0) === 429) {
                header('Retry-After: ' . (int) ($response['retry_after'] ?? 60));
                $this->sendApplicationDecision(429, 'block', 'Too many requests', 'rate_limited');
                $this->metrics->maybeFlush();
                exit;
            }
            $shouldContinue = $this->applyFailMode(
                $requestPath,
                $fingerprint,
                $sid,
                CloudClient::usesConfiguredFailMode($response)
            );
            $this->metrics->maybeFlush();
            if (!$shouldContinue) {
                exit;
            }
            return;
        }

        $data = is_array($response['data']) ? $response['data'] : [];
        $decisionRaw = $data['decision'] ?? null;
        $decision = is_string($decisionRaw) ? strtolower(trim($decisionRaw)) : '';

        if (isset($data['route_bundle']) && is_array($data['route_bundle'])) {
            if ($this->bundleAccepted($data['route_bundle'], 'route_bundle')) {
                $this->storeRouteBundle($data['route_bundle']);
            } else {
                $this->log('Rejected route_bundle due to signature policy', 'warning');
            }
            $routeBundle = $this->getRouteBundle();
        }
        if (isset($data['policy_bundle']) && is_array($data['policy_bundle'])) {
            if ($this->bundleAccepted($data['policy_bundle'], 'policy_bundle')) {
                $this->storePolicyBundle($data['policy_bundle']);
            } else {
                $this->log('Rejected policy_bundle due to signature policy', 'warning');
            }
        }

        if (($data['challenge_type'] ?? null) === 'browser_escape') {
            $page = BrowserEscape::page($data, $server);
            if ($page === null) {
                $this->metrics->recordCloudError('browser_escape_contract');
                $this->sendApplicationDecision(503, 'block', 'Service unavailable', 'browser_escape_contract');
            } else {
                if ($page['phase'] === 'probe') {
                    BrowserEscape::setCookie(BrowserEscape::CHECKED_COOKIE, $server, $this->trustedProxyCfg);
                }
                http_response_code(200);
                header('Cache-Control: private, no-store');
                header('Content-Type: text/html; charset=utf-8');
                echo $page['html'];
            }
            $this->metrics->maybeFlush();
            exit;
        }

        if ($decision === 'allow') {
            // A browser proof may be reused; a policy decision never authorizes another request.
            header('Cache-Control: private, no-store');
            $this->clearChallengeLoop($fingerprint);
            if (is_string($data['sid'] ?? null) && $data['sid'] !== '') {
                $this->cache->set($this->fpSidKey($fingerprint), $data['sid'], 3600);
                $sid = (string) $data['sid'];
            }
            $this->metrics->recordDecision('allow');
            if ($sid !== '') {
                $this->metrics->recordSessionDecision($sid, 'allow', $requestPath);
            }
            $this->metrics->maybeFlush();
            return;
        }

        if ($decision === 'whitepage') {
            $this->clearChallengeLoop($fingerprint);
            $this->metrics->recordDecision('whitepage');
            if ($sid !== '') {
                $this->metrics->recordSessionDecision($sid, 'whitepage', $requestPath);
            }

            $whitepageHtml = is_string($data['whitepage_page']['html'] ?? null)
                ? trim((string) $data['whitepage_page']['html'])
                : '';
            if ($whitepageHtml === '') {
                $whitepageHtml = '<!doctype html><html><body><h1>Please continue later</h1></body></html>';
            }
            $this->sendApplicationDecision(200, 'whitepage', $whitepageHtml);
            $this->metrics->maybeFlush();
            exit;
        }

        if ($decision === 'block') {
            $this->clearChallengeLoop($fingerprint);
            $this->metrics->recordDecision('block');
            if ($sid !== '') {
                $this->metrics->recordSessionDecision($sid, 'block', $requestPath);
            }

            $whitepageOverride = BotBlockPageResolver::resolve(
                $this->config,
                $fingerprint . '|' . $requestPath . '|' . $sid
            );
            if ($whitepageOverride !== null) {
                $this->sendApplicationDecision(200, 'whitepage', (string) ($whitepageOverride['html'] ?? ''));
                $this->metrics->maybeFlush();
                exit;
            }

            $blockHtml = is_string($data['block_page']['html'] ?? null) ? (string) $data['block_page']['html'] : '';
            if ($blockHtml === '') {
                $blockHtml = '<!doctype html><html><body><h1>Access denied</h1></body></html>';
            }
            $this->sendApplicationDecision(403, 'block', $blockHtml);
            $this->metrics->maybeFlush();
            exit;
        }

        if ($decision === 'challenge') {
            if ($this->registerChallengeLoop($fingerprint)) {
                $this->metrics->recordRateLimit('loop');
                $shouldContinue = $this->handleLoopExceeded($requestPath, $fingerprint, $sid);
                $this->metrics->maybeFlush();
                if (!$shouldContinue) {
                    exit;
                }
                return;
            }

            $this->metrics->recordDecision('challenge');
            if ($sid !== '') {
                $this->metrics->recordSessionDecision($sid, 'challenge', $requestPath);
            }

            $rid = trim((string) ($data['rid'] ?? ''));
            if ($rid === '') {
                $rid = Utils::randomToken(28);
            }

            $csrf = Utils::randomToken(24);
            $ridTtl = max(60, $this->config->getInt('rid_ttl_sec', 180));

            $originalUrl = Utils::requestTarget($server);
            $returnUrl = '/';
            if (Utils::sameOrigin($server, (string) ($server['HTTP_REFERER'] ?? ''), $this->trustedProxyCfg)) {
                $referer = parse_url((string) $server['HTTP_REFERER']);
                $returnUrl = Utils::requestTarget(['REQUEST_URI' => ($referer['path'] ?? '/')
                    . (isset($referer['query']) ? '?' . $referer['query'] : '')]);
            }
            $state = [
                'rid' => $rid,
                'csrf' => $csrf,
                'fingerprint' => $fingerprint,
                'original_url' => $originalUrl,
                'original_path' => $requestPath,
                'browser_navigation' => Utils::isDocumentNavigation($server),
                'return_url' => $returnUrl,
                'created_at' => time(),
                'tries' => 0,
                'route_bundle_id' => $routeBundle['current']['id'] ?? null,
            ];
            $this->cache->set($this->ridKey($rid), $state, $ridTtl);

            $challengePath = $this->routePath($routeBundle, 'challenge_path');
            $challengeUrl = Utils::joinBaseAndRoute($basePath, $challengePath);
            $challengeUrl = Utils::appendQueryParam($challengeUrl, 'rid', $rid);

            if (!Utils::isDocumentNavigation($server)) {
                http_response_code(403);
                header('Cache-Control: no-store');
                header('Content-Type: application/json; charset=utf-8');
                if (strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')) !== 'HEAD') {
                    echo json_encode(['ok' => false, 'decision' => 'challenge', 'error' => 'challenge_required', 'challenge_url' => $challengeUrl], JSON_UNESCAPED_SLASHES);
                }
                $this->metrics->maybeFlush();
                exit;
            }

            http_response_code(302);
            header('Cache-Control: no-store');
            header('Location: ' . $challengeUrl, true, 302);
            $this->metrics->maybeFlush();
            exit;
        }

        $this->metrics->recordCloudError('check_contract');
        $shouldContinue = $this->applyFailMode($requestPath, $fingerprint, $sid);
        $this->metrics->maybeFlush();
        if (!$shouldContinue) {
            exit;
        }
    }

    public function updateAssets(): int
    {
        $updater = new AssetUpdater($this->config, $this->cloudClient);
        $updater->setLogger(function (string $level, string $message): void {
            $this->log($message, $level);
        });
        return $updater->run();
    }

    public function updateModule(): int
    {
        $updater = new ModuleUpdater($this->config, $this->cloudClient);
        $updater->setLogger(function (string $level, string $message): void {
            $this->log($message, $level);
        });
        return $updater->run();
    }

    private function consumeCheckRateLimit(array $server): bool
    {
        $ip = $this->clientIp($server);
        $limits = $this->config->getArray('rate_limits');
        $cfg = $limits['check'] ?? ['rate_per_sec' => 1.0, 'burst' => 60];
        return $this->rateLimiter->consume(
            'check:' . $ip,
            (float) ($cfg['rate_per_sec'] ?? 1.0),
            (int) ($cfg['burst'] ?? 60)
        );
    }

    private function applyFailMode(
        string $path,
        string $fingerprint,
        string $sid,
        bool $allowConfiguredFailOpen = true
    ): bool
    {
        if ($allowConfiguredFailOpen && $this->shouldFailOpen($path)) {
            $this->cache->set($this->failOpenKey($fingerprint, $path), 1, 60);
            $this->metrics->recordDecision('allow');
            if ($sid !== '') {
                $this->metrics->recordSessionDecision($sid, 'allow', $path);
            }
            return true;
        }

        $this->metrics->recordDecision('block');
        if ($sid !== '') {
            $this->metrics->recordSessionDecision($sid, 'block', $path);
        }
        $this->sendApplicationDecision(503, 'block', 'Service unavailable', 'service_unavailable');
        return false;
    }

    private function sendApplicationDecision(int $status, string $decision, string $html, ?string $error = null): void
    {
        http_response_code($status);
        header('Cache-Control: no-store');
        $navigation = Utils::isDocumentNavigation($this->requestServer);
        header('Content-Type: ' . ($navigation ? 'text/html' : 'application/json') . '; charset=utf-8');
        if (strtoupper((string) ($this->requestServer['REQUEST_METHOD'] ?? 'GET')) === 'HEAD') {
            return;
        }
        echo $navigation ? $html : json_encode(['ok' => false, 'decision' => $decision, 'error' => $error ?? $decision], JSON_UNESCAPED_SLASHES);
    }

    private function shouldFailOpen(string $path): bool
    {
        return $this->config->shouldFailOpen($path, $this->cache);
    }

    private function latencyBucket(int $ms): string
    {
        if ($ms <= 100) {
            return 'p100';
        }
        if ($ms <= 300) {
            return 'p300';
        }
        if ($ms <= 800) {
            return 'p800';
        }
        return 'p800_plus';
    }

    private function isExcludedPath(string $path): bool
    {
        $excluded = $this->config->pathPrefixes('excluded_path_prefixes', $this->cache);
        foreach ($excluded as $prefix) {
            if (!is_string($prefix) || $prefix === '') {
                continue;
            }
            if (Utils::pathMatchesPrefix($path, $prefix)) {
                return true;
            }
        }
        return false;
    }

    private function getRouteBundle(): array
    {
        $fromCache = $this->cache->get(self::ROUTE_BUNDLE_KEY, null);
        if (is_array($fromCache)) {
            if ($this->isFreshCachedRouteBundle($fromCache)) {
                $normalized = $this->normalizeRouteBundleForRuntime($fromCache);
                if ($this->isValidRouteBundle($normalized)) {
                    return $normalized;
                }
            }
            $this->cache->delete(self::ROUTE_BUNDLE_KEY);
        }

        $fallback = $this->config->getArray('route_bundle');
        $normalizedFallback = $this->normalizeRouteBundleForRuntime($fallback);
        if ($this->isValidRouteBundle($normalizedFallback)) {
            return $normalizedFallback;
        }

        return [
            'current' => [
                'id' => 'fallback',
                'challenge_path' => '/c/fallback',
                'solve_path' => '/s/fallback',
                'session_ingest_path' => '/e/fallback',
                'metrics_ingest_path' => '/m/fallback',
            ],
            'prev' => null,
        ];
    }

    private function storeRouteBundle(array $bundle): void
    {
        $bundle = $this->normalizeRouteBundleForRuntime($bundle);
        if (!$this->isValidRouteBundle($bundle)) {
            return;
        }

        $existing = $this->cache->get(self::ROUTE_BUNDLE_KEY, null);
        if (is_array($existing) && !$this->isFreshCachedRouteBundle($existing)) {
            $this->cache->delete(self::ROUTE_BUNDLE_KEY);
            $existing = null;
        }
        $existing = is_array($existing) ? $this->normalizeRouteBundleForRuntime($existing) : null;

        $current = $bundle['current'];
        $incomingPrev = $this->validRouteEntryOrNull($bundle['prev'] ?? null);
        if ($incomingPrev === null && is_array($existing)) {
            $existingCurrent = $this->validRouteEntryOrNull($existing['current'] ?? null);
            if (
                is_array($existingCurrent)
                && isset($existingCurrent['id'], $current['id'])
                && (string) $existingCurrent['id'] !== (string) $current['id']
            ) {
                $incomingPrev = $existingCurrent;
            }
        }

        if (
            is_array($incomingPrev)
            && isset($incomingPrev['id'], $current['id'])
            && (string) $incomingPrev['id'] === (string) $current['id']
        ) {
            $incomingPrev = null;
        }

        if (!$this->isValidRouteBundle(['current' => $current, 'prev' => $incomingPrev])) {
            return;
        }

        $now = time();
        $ttl = max(60, (int) ($bundle['ttl'] ?? $this->routePolicyInt('default_ttl_sec', 900)));
        $prevGrace = max(
            $this->config->getInt('rid_ttl_sec', 180) + 30,
            $this->routePolicyInt('prev_grace_sec', 600)
        );
        $persistTtl = max($ttl + $prevGrace + 60, $this->routePolicyInt('persist_ttl_sec', 86400));

        $stored = [
            'current' => $current,
            'prev' => $incomingPrev,
            'ttl' => $ttl,
            'meta' => [
                'stored_at' => $now,
                'current_expires_at' => $now + $ttl,
                'prev_expires_at' => is_array($incomingPrev) ? ($now + $prevGrace) : 0,
            ],
        ];
        $this->cache->set(self::ROUTE_BUNDLE_KEY, $stored, $persistTtl);
    }

    private function isFreshCachedRouteBundle(array $bundle): bool
    {
        $meta = $bundle['meta'] ?? null;
        if (!is_array($meta)) {
            return false;
        }
        $expiresAt = $meta['current_expires_at'] ?? null;
        return is_int($expiresAt) && $expiresAt > time();
    }

    private function isValidRouteBundle(array $bundle): bool
    {
        if (!isset($bundle['current']) || !is_array($bundle['current']) || !$this->isValidRouteEntry($bundle['current'])) {
            return false;
        }

        if (isset($bundle['prev']) && $bundle['prev'] !== null) {
            if (!is_array($bundle['prev']) || !$this->isValidRouteEntry($bundle['prev'])) {
                return false;
            }
        }

        $owners = [];
        foreach (['current', 'prev'] as $slot) {
            $entry = $bundle[$slot] ?? null;
            if (!is_array($entry)) {
                continue;
            }
            foreach (['challenge_path', 'solve_path', 'session_ingest_path', 'metrics_ingest_path'] as $type) {
                $path = $entry[$type];
                if (isset($owners[$path]) && $owners[$path] !== $type) {
                    return false;
                }
                $owners[$path] = $type;
            }
        }

        return true;
    }

    private function routePath(array $bundle, string $key): string
    {
        $path = $bundle['current'][$key] ?? '/';
        if (!is_string($path) || $path === '') {
            $path = '/';
        }
        return Utils::normalizeRoutePath($path, $this->config->getString('base_path'));
    }

    private function consumeContinuation(string $fingerprint, array $server): bool
    {
        $origin = (string) ($server['HTTP_ORIGIN'] ?? '');
        $referer = (string) ($server['HTTP_REFERER'] ?? '');
        if (($origin !== '' && !Utils::sameOrigin($server, $origin, $this->trustedProxyCfg))
            || ($referer !== '' && !Utils::sameOrigin($server, $referer, $this->trustedProxyCfg))
            || $referer === ''
            || strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')) !== 'GET'
        ) {
            return false;
        }
        $key = 'ys:continue:' . $fingerprint . ':' . hash('sha256', Utils::requestTarget($server));
        parse_str((string) parse_url($referer, PHP_URL_QUERY), $query);
        $rid = $query['rid'] ?? null;
        $expected = $this->cache->get($key, null);
        if (!is_string($rid) || !is_string($expected) || $rid === '' || !hash_equals($expected, $rid)) {
            return false;
        }
        $allowed = false;
        $this->cache->mutate($key, 120, static function ($value) use (&$allowed, $expected) {
            $allowed = $value === $expected;
            return 0;
        });
        return $allowed;
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

    private function isValidRouteEntry(array $entry): bool
    {
        $reserved = ['/health' => true, '/debug/self-test' => true];
        foreach (['challenge_path', 'solve_path', 'session_ingest_path', 'metrics_ingest_path'] as $key) {
            $path = $entry[$key] ?? null;
            if (!is_string($path) || $path === '' || isset($reserved[$path])) {
                return false;
            }
        }
        return true;
    }

    private function validRouteEntryOrNull(mixed $entry): ?array
    {
        if (!is_array($entry)) {
            return null;
        }
        $normalized = $entry;
        foreach (['challenge_path', 'solve_path', 'session_ingest_path', 'metrics_ingest_path'] as $key) {
            $path = $entry[$key] ?? null;
            if (
                !is_string($path)
                || trim($path) === ''
                || !str_starts_with(trim($path), '/')
                || str_contains($path, "\0")
                || str_contains($path, '?')
                || str_contains($path, '#')
            ) {
                return null;
            }
            $normalizedPath = $this->normalizeBundleRoutePath(trim($path));
            if ($normalizedPath === null) {
                return null;
            }
            $normalized[$key] = $normalizedPath;
        }
        return $this->isValidRouteEntry($normalized) ? $normalized : null;
    }

    private function normalizeBundleRoutePath(string $path): ?string
    {
        $path = Utils::normalizeRoutePath($path, $this->config->getString('base_path'));
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                if ($segments === []) {
                    return null;
                }
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }
        return '/' . implode('/', $segments);
    }

    private function normalizeRouteBundleForRuntime(array $bundle): array
    {
        $current = $this->validRouteEntryOrNull($bundle['current'] ?? null);
        $prev = $this->validRouteEntryOrNull($bundle['prev'] ?? null);
        $ttl = (int) ($bundle['ttl'] ?? $this->routePolicyInt('default_ttl_sec', 900));

        if (is_array($prev)) {
            $now = time();
            $meta = is_array($bundle['meta'] ?? null) ? $bundle['meta'] : [];
            $prevExpiresAt = (int) ($meta['prev_expires_at'] ?? 0);
            if ($prevExpiresAt > 0 && $now > $prevExpiresAt) {
                $prev = null;
            }
        }

        if (!is_array($current)) {
            return ['current' => null, 'prev' => null, 'ttl' => $ttl];
        }

        $normalized = [
            'current' => $current,
            'prev' => $prev,
            'ttl' => $ttl,
        ];
        if (is_array($bundle['meta'] ?? null)) {
            $normalized['meta'] = $bundle['meta'];
        }

        return $normalized;
    }

    private function routePolicyInt(string $key, int $default): int
    {
        $policy = $this->config->getArray('route_bundle_policy');
        $value = $policy[$key] ?? $default;
        return is_numeric($value) ? (int) $value : $default;
    }

    private function storePolicyBundle(array $bundle): void
    {
        $excluded = $this->sanitizePrefixList($bundle['excluded_path_prefixes'] ?? []);
        $strict = $this->sanitizePrefixList($bundle['strict_path_prefixes'] ?? []);

        $ttl = (int) ($bundle['ttl'] ?? 900);
        $ttl = max(60, $ttl);
        $stored = [
            'excluded_path_prefixes' => $excluded,
            'strict_path_prefixes' => $strict,
            'ttl' => $ttl,
            'stored_at' => time(),
        ];
        $persistTtl = max($ttl + 60, 3600);
        $this->cache->set(self::POLICY_BUNDLE_KEY, $stored, $persistTtl);
    }

    private function sanitizePrefixList(mixed $list): array
    {
        if (!is_array($list)) {
            return [];
        }

        $out = [];
        foreach ($list as $prefix) {
            if (!is_string($prefix)) {
                continue;
            }
            $prefix = trim($prefix);
            if ($prefix === '') {
                continue;
            }
            if (!str_starts_with($prefix, '/')) {
                $prefix = '/' . $prefix;
            }
            $out[] = rtrim($prefix, '/') === '' ? '/' : rtrim($prefix, '/');
        }
        return array_values(array_unique($out));
    }

    private function loopKey(string $fingerprint): string
    {
        return 'ys:loop:' . $fingerprint;
    }

    private function registerChallengeLoop(string $fingerprint): bool
    {
        $loopCfg = $this->config->getArray('loop_protection');
        $enabled = (bool) ($loopCfg['enabled'] ?? true);
        if (!$enabled) {
            return false;
        }

        $ttl = max(30, is_numeric($loopCfg['ttl_sec'] ?? null) ? (int) $loopCfg['ttl_sec'] : 120);
        $maxChallenges = max(1, is_numeric($loopCfg['max_challenges'] ?? null) ? (int) $loopCfg['max_challenges'] : 5);

        $state = $this->cache->mutate(
            $this->loopKey($fingerprint),
            $ttl,
            static function ($current): array {
                $data = is_array($current) ? $current : [];
                $count = (int) ($data['count'] ?? 0) + 1;
                return [
                    'count' => $count,
                    'updated_at' => time(),
                ];
            },
            ['count' => 0, 'updated_at' => time()]
        );

        $count = is_array($state) ? (int) ($state['count'] ?? 0) : 0;
        return $count > $maxChallenges;
    }

    private function clearChallengeLoop(string $fingerprint): void
    {
        $this->cache->delete($this->loopKey($fingerprint));
    }

    private function handleLoopExceeded(string $path, string $fingerprint, string $sid): bool
    {
        $this->metrics->recordDecision('block');
        if ($sid !== '') {
            $this->metrics->recordSessionDecision($sid, 'block', $path);
        }
        header('Retry-After: 1');
        $this->sendApplicationDecision(429, 'block', 'Too many challenges', 'challenge_rate_limited');
        return false;
    }

    private function log(string $message, string $level = 'info'): void
    {
        $message = Utils::redactSecrets($message, [
            $this->config->getString('secret'),
            $this->config->getString('site_key'),
        ]);

        if ($this->logger !== null) {
            ($this->logger)($level, $message);
            return;
        }

        $line = rtrim($message) . "\n";
        if (PHP_SAPI !== 'cli') {
            error_log('[YourShield][' . $level . '] ' . rtrim($message));
            return;
        }
        if ($level === 'error' && defined('STDERR')) {
            fwrite(STDERR, $line);
            return;
        }
        if (defined('STDOUT')) {
            fwrite(STDOUT, $line);
            return;
        }
        echo $line;
    }

    private function clientIp(array $server): string
    {
        return Utils::clientIp($server, $this->trustedProxyCfg);
    }

    /**
     * Extract browser headers worth forwarding to the cloud API for bot detection.
     *
     * @return array<string, string>
     */
    private static function collectForwardedHeaders(array $server): array
    {
        // Map of HTTP header name → $_SERVER key
        $map = [
            'sec-ch-ua'         => 'HTTP_SEC_CH_UA',
            'sec-ch-ua-mobile'  => 'HTTP_SEC_CH_UA_MOBILE',
            'sec-ch-ua-platform'=> 'HTTP_SEC_CH_UA_PLATFORM',
            'sec-fetch-site'    => 'HTTP_SEC_FETCH_SITE',
            'sec-fetch-mode'    => 'HTTP_SEC_FETCH_MODE',
            'sec-fetch-dest'    => 'HTTP_SEC_FETCH_DEST',
            'accept'            => 'HTTP_ACCEPT',
            'accept-encoding'   => 'HTTP_ACCEPT_ENCODING',
            'accept-language'   => 'HTTP_ACCEPT_LANGUAGE',
        ];

        $result = [];
        foreach ($map as $headerName => $serverKey) {
            $value = $server[$serverKey] ?? null;
            if (is_string($value) && $value !== '') {
                $result[$headerName] = $value;
            }
        }

        // Preserve canonical outgoing names while accepting common proxy/CDN aliases.
        $tlsAliases = [
            'x-ja3-hash' => [
                'HTTP_X_JA3_HASH',
                'HTTP_X_JA3',
                'HTTP_CF_JA3',
                'HTTP_JA3_HASH',
                'HTTP_JA3',
                'SSL_JA3',
                'JA3',
            ],
            'x-ja4-hash' => [
                'HTTP_X_JA4_HASH',
                'HTTP_X_JA4',
                'HTTP_CF_JA4',
                'HTTP_JA4_HASH',
                'HTTP_JA4',
                'SSL_JA4',
                'JA4',
            ],
        ];
        foreach ($tlsAliases as $headerName => $serverKeys) {
            foreach ($serverKeys as $serverKey) {
                $normalized = self::normalizeTlsFingerprintHeader($server[$serverKey] ?? null);
                if ($normalized !== null) {
                    $result[$headerName] = $normalized;
                    break;
                }
            }
        }

        return $result;
    }

    private static function normalizeTlsFingerprintHeader(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $normalized = strtolower(trim($value));
        if ($normalized === '') {
            return null;
        }
        return strlen($normalized) <= 256 ? $normalized : null;
    }

    private function bundleAccepted(array $bundle, string $kind): bool
    {
        $mode = strtolower(trim((string) ($this->bundleSignatureCfg['mode'] ?? 'optional')));
        if (!in_array($mode, ['off', 'optional', 'required'], true)) {
            $mode = 'optional';
        }
        if ($mode === 'off') {
            return true;
        }

        $hasSignature = is_string($bundle['sig'] ?? null) && trim((string) $bundle['sig']) !== '';
        if (!$hasSignature) {
            return $mode !== 'required';
        }

        $key = trim((string) ($this->bundleSignatureCfg['key'] ?? ''));
        if ($key === '') {
            $key = $this->config->getString('secret');
        }
        if ($key === '') {
            return false;
        }

        $maxAgeSec = (int) ($this->bundleSignatureCfg['max_age_sec'] ?? 1800);
        $maxAgeSec = max(0, $maxAgeSec);
        return Utils::verifyBundleSignature($bundle, $kind, $key, $maxAgeSec);
    }

    private function maybeTriggerAutoAssetsUpdate(array $server): void
    {
        $assetsCfg = $this->config->getArray('assets');
        $autoCfg = is_array($assetsCfg['auto_update'] ?? null) ? $assetsCfg['auto_update'] : [];
        $enabled = (bool) ($autoCfg['enabled'] ?? false);
        if (!$enabled) {
            return;
        }

        $onHtmlOnly = !array_key_exists('on_html_only', $autoCfg) || (bool) $autoCfg['on_html_only'];
        if ($onHtmlOnly && !Utils::isHtmlRequest($server)) {
            return;
        }

        if (!$this->canAutoUpdateAssets()) {
            return;
        }

        $intervalSec = max(60, is_numeric($autoCfg['interval_sec'] ?? null) ? (int) $autoCfg['interval_sec'] : 900);
        $lockTtlSec = max(3, min(30, is_numeric($autoCfg['lock_ttl_sec'] ?? null) ? (int) $autoCfg['lock_ttl_sec'] : 6));
        $retry = max(60, min(300, intdiv($intervalSec, 3)));
        $now = time();
        $nextAt = $this->scheduledUpdaterNextAt(self::ASSETS_AUTO_NEXT_KEY, 'assets', $retry, $now);
        if ($nextAt > $now) {
            return;
        }

        if (!$this->cache->add(self::ASSETS_AUTO_LOCK_KEY, 1, $lockTtlSec)) {
            return;
        }

        try {
            $nextAt = $this->scheduledUpdaterNextAt(self::ASSETS_AUTO_NEXT_KEY, 'assets', $retry, $now);
            if ($nextAt > $now) {
                return;
            }

            $this->cache->set(self::ASSETS_AUTO_NEXT_KEY, $now + $intervalSec, $intervalSec + 600);
            if (!$this->spawnUpdaterProcess('assets', $server)) {
                $this->cache->set(self::ASSETS_AUTO_NEXT_KEY, $now + $retry, $retry + 120);
                $this->log('Auto assets update trigger failed: unable to spawn updater process', 'warning');
            }
        } finally {
            $this->cache->delete(self::ASSETS_AUTO_LOCK_KEY);
        }
    }

    private function canAutoUpdateAssets(): bool
    {
        $siteKey = $this->config->getString('site_key');
        $secret = $this->config->getString('secret');
        $cloud = $this->config->getString('cloud_base_url');
        if ($siteKey === '' || $siteKey === 'replace-with-site-key') {
            return false;
        }
        if ($secret === '' || $secret === 'replace-with-secret') {
            return false;
        }
        if ($cloud === '' || str_contains($cloud, 'cloud.example.com')) {
            return false;
        }
        return true;
    }

    private function scheduledUpdaterNextAt(string $cacheKey, string $component, int $retrySec, int $now): int
    {
        $scheduledAt = (int) $this->cache->get($cacheKey, 0);
        $nextAt = $this->updaterNextAt($component, $scheduledAt, $retrySec);
        if ($nextAt !== $scheduledAt) {
            $this->cache->set($cacheKey, $nextAt, max(120, $nextAt - $now + 120));
        }
        return $nextAt;
    }

    private function updaterNextAt(string $component, int $scheduledAt, int $retrySec): int
    {
        $path = rtrim($this->config->getString('cache_dir'), '/') . '/' . $component . '-updater.status.json';
        $raw = @file_get_contents($path);
        if (!is_string($raw) || strlen($raw) > 4096) {
            return $scheduledAt;
        }
        $status = json_decode($raw, true);
        if (
            !is_array($status)
            || ($status['status'] ?? '') !== 'finished'
            || ($status['component'] ?? '') !== $component
            || !is_numeric($status['exit_code'] ?? null)
            || (int) $status['exit_code'] === 0
        ) {
            return $scheduledAt;
        }
        $finishedAt = is_numeric($status['finished_at'] ?? null) ? (int) $status['finished_at'] : 0;
        if ($finishedAt <= 0) {
            return $scheduledAt;
        }
        $retryAt = $finishedAt + max(1, $retrySec);
        return $scheduledAt > 0 ? min($scheduledAt, $retryAt) : $retryAt;
    }

    private function spawnUpdaterProcess(string $component, array $server): bool
    {
        $moduleRoot = defined('YS_MODULE_ROOT') && is_string(constant('YS_MODULE_ROOT'))
            ? rtrim((string) constant('YS_MODULE_ROOT'), '/\\')
            : dirname(__DIR__);
        $scripts = [
            'assets' => $moduleRoot . '/updater.php',
            'module' => $moduleRoot . '/module_updater.php',
        ];
        $scriptPath = $scripts[$component] ?? '';
        if ($scriptPath === '' || !is_file($scriptPath)) {
            return false;
        }

        $php = Utils::resolvePhpCli($this->config->getString('php_cli'));
        $host = Utils::resolveSiteHost($server, $this->config->getString('site_host'));
        if ($php === null || $host === '') {
            return false;
        }

        $statusPath = rtrim($this->config->getString('cache_dir'), '/') . '/' . $component . '-updater.status.json';
        if (!$this->writeUpdaterStatus($statusPath, [
            'status' => 'spawned',
            'component' => $component,
            'host' => $host,
            'spawned_at' => time(),
        ])) {
            return false;
        }

        $statusTmp = $statusPath . '.tmp';
        $statusFormat = '{"status":"finished","component":"' . $component
            . '","host":"' . $host . '","exit_code":%d,"finished_at":%d}' . "\n";
        $windows = DIRECTORY_SEPARATOR === '\\';
        $cmd = self::buildUpdaterCommand(
            $php,
            $component,
            $scriptPath,
            $host,
            $statusPath,
            $statusTmp,
            $statusFormat,
            $windows
        );
        $out = [];
        $code = 1;
        @exec($cmd, $out, $code);
        return $code === 0 && ($windows || (isset($out[0]) && ctype_digit(trim((string) $out[0]))));
    }

    private static function buildUpdaterCommand(
        string $php,
        string $component,
        string $scriptPath,
        string $host,
        string $statusPath,
        string $statusTmp,
        string $statusFormat,
        bool $windows
    ): string {
        if ($windows) {
            $code = 'require_once ' . var_export(__DIR__ . '/autoload.php', true) . ';'
                . 'exit(\\YourShield\\Agent::runUpdaterChild('
                . var_export($component, true) . ','
                . var_export(dirname($scriptPath), true) . ','
                . var_export($host, true) . ','
                . var_export($statusPath, true)
                . '));';
            return 'start "" /B ' . escapeshellarg($php) . ' -r ' . escapeshellarg($code) . ' >NUL 2>&1';
        }

        return '(HTTP_HOST=' . escapeshellarg($host)
            . ' YS_SITE_HOST=' . escapeshellarg($host)
            . ' ' . escapeshellarg($php)
            . ' ' . escapeshellarg($scriptPath)
            . '; child_status=$?; umask 077; printf ' . escapeshellarg($statusFormat)
            . ' "$child_status" "$(date +%s)" > ' . escapeshellarg($statusTmp)
            . ' && mv -f ' . escapeshellarg($statusTmp) . ' ' . escapeshellarg($statusPath)
            . '; exit "$child_status") >/dev/null 2>&1 & echo $!';
    }

    public static function runUpdaterChild(
        string $component,
        string $moduleRoot,
        string $host,
        string $statusPath
    ): int {
        if (!in_array($component, ['assets', 'module'], true) || Utils::canonicalHost($host) !== $host) {
            return 1;
        }

        try {
            putenv('HTTP_HOST=' . $host);
            putenv('YS_SITE_HOST=' . $host);
            $_SERVER['HTTP_HOST'] = $host;
            $config = RuntimeConfig::fromFile(rtrim($moduleRoot, '/\\') . '/config.php');
            $cacheDir = $config->getString('cache_dir');
            if (
                basename($statusPath) !== $component . '-updater.status.json'
                || !Utils::pathIsInside($cacheDir, $statusPath)
                || !Utils::pathIsInside(dirname($statusPath), $cacheDir)
            ) {
                return 1;
            }
            $agent = new self($config);
            $exitCode = $component === 'assets' ? $agent->updateAssets() : $agent->updateModule();
            if (!$agent->writeUpdaterStatus($statusPath, [
                'status' => 'finished',
                'component' => $component,
                'host' => $host,
                'exit_code' => $exitCode,
                'finished_at' => time(),
            ])) {
                return $exitCode === 0 ? 1 : $exitCode;
            }
            return $exitCode;
        } catch (\Throwable) {
            return 1;
        }
    }

    private function writeUpdaterStatus(string $path, array $status): bool
    {
        $encoded = json_encode($status, JSON_UNESCAPED_SLASHES);
        if (!is_string($encoded)) {
            return false;
        }
        $tmp = $path . '.write.' . Utils::randomToken(6);
        if (file_put_contents($tmp, $encoded . "\n", LOCK_EX) === false) {
            return false;
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }

    private function maybeTriggerAutoModuleUpdate(array $server): void
    {
        $cfg = $this->config->getArray('module_update');
        $enabled = (bool) ($cfg['enabled'] ?? false);
        if (!$enabled) {
            return;
        }

        $onHtmlOnly = !array_key_exists('on_html_only', $cfg) || (bool) ($cfg['on_html_only']);
        if ($onHtmlOnly && !Utils::isHtmlRequest($server)) {
            return;
        }

        if (!$this->canAutoUpdateAssets()) {
            return;
        }

        $intervalSec = max(300, is_numeric($cfg['interval_sec'] ?? null) ? (int) ($cfg['interval_sec']) : 21600);
        $lockTtlSec = max(3, min(30, is_numeric($cfg['lock_ttl_sec'] ?? null) ? (int) ($cfg['lock_ttl_sec']) : 6));
        $retry = max(300, min(1800, intdiv($intervalSec, 3)));
        $now = time();

        $nextAt = $this->scheduledUpdaterNextAt(self::MODULE_AUTO_NEXT_KEY, 'module', $retry, $now);
        if ($nextAt > $now) {
            return;
        }

        if (!$this->cache->add(self::MODULE_AUTO_LOCK_KEY, 1, $lockTtlSec)) {
            return;
        }

        try {
            $nextAt = $this->scheduledUpdaterNextAt(self::MODULE_AUTO_NEXT_KEY, 'module', $retry, $now);
            if ($nextAt > $now) {
                return;
            }

            $this->cache->set(self::MODULE_AUTO_NEXT_KEY, $now + $intervalSec, $intervalSec + 600);
            if (!$this->spawnUpdaterProcess('module', $server)) {
                $this->cache->set(self::MODULE_AUTO_NEXT_KEY, $now + $retry, $retry + 120);
                $this->log('Auto module update trigger failed: unable to spawn module_updater.php', 'warning');
            }
        } finally {
            $this->cache->delete(self::MODULE_AUTO_LOCK_KEY);
        }
    }

}
