<?php
declare(strict_types=1);

namespace YourShield;

final class Utils
{
    public static function canonicalAbsolutePath(string $path): ?string
    {
        $path = str_replace('\\', '/', trim($path));
        if ($path === '' || str_contains($path, "\0")) {
            return null;
        }

        $prefix = '';
        if (preg_match('/^[A-Za-z]:\//', $path) === 1) {
            $prefix = strtoupper($path[0]) . ':/';
            $path = substr($path, 3);
        } elseif (DIRECTORY_SEPARATOR === '\\' && str_starts_with($path, '//')) {
            $parts = array_values(array_filter(explode('/', substr($path, 2)), 'strlen'));
            if (count($parts) < 2) {
                return null;
            }
            $prefix = '//' . array_shift($parts) . '/' . array_shift($parts);
            $path = implode('/', $parts);
        } elseif (str_starts_with($path, '/')) {
            $prefix = '/';
            $path = ltrim($path, '/');
        } else {
            return null;
        }

        $segments = array_values(array_filter(explode('/', $path), 'strlen'));
        foreach ($segments as $segment) {
            if ($segment === '.' || $segment === '..') {
                return null;
            }
        }

        for ($count = count($segments); $count >= 0; $count--) {
            $candidate = $count === 0 ? $prefix : rtrim($prefix, '/');
            $head = array_slice($segments, 0, $count);
            if ($head !== []) {
                $candidate .= '/' . implode('/', $head);
            }
            if (!file_exists($candidate) && !is_link($candidate)) {
                continue;
            }

            $resolved = realpath($candidate);
            if ($resolved === false) {
                return null;
            }
            $resolved = rtrim(str_replace('\\', '/', $resolved), '/');
            if ($resolved === '') {
                $resolved = '/';
            }
            $tail = array_slice($segments, $count);
            return $tail === []
                ? $resolved
                : rtrim($resolved, '/') . '/' . implode('/', $tail);
        }

        return null;
    }

    public static function pathIsInside(string $root, string $path): bool
    {
        $root = self::canonicalAbsolutePath($root);
        $path = self::canonicalAbsolutePath($path);
        if ($root === null || $path === null) {
            return false;
        }
        if (DIRECTORY_SEPARATOR === '\\') {
            $root = strtolower($root);
            $path = strtolower($path);
        }
        if ($root === '/') {
            return str_starts_with($path, '/');
        }
        return $path === $root || str_starts_with($path, rtrim($root, '/') . '/');
    }

    public static function ownershipIssue(string $configLocalPath, ?int $effectiveUid = null): ?string
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            return null;
        }
        if ($effectiveUid === null) {
            static $detectedUid = null;
            if ($detectedUid === null) {
                if (function_exists('posix_geteuid')) {
                    $detectedUid = posix_geteuid();
                } else {
                    $probe = @tempnam(sys_get_temp_dir(), '.ys-uid-');
                    $detectedUid = is_string($probe) ? fileowner($probe) : false;
                    if (is_string($probe)) {
                        @unlink($probe);
                    }
                }
            }
            if (!is_int($detectedUid)) {
                return 'Cannot verify the POSIX runtime user.';
            }
            $effectiveUid = $detectedUid;
        }
        if ($effectiveUid === 0) {
            return 'Refusing to run as root; use runuser/sudo -u with the PHP-FPM site user.';
        }
        clearstatcache(true, $configLocalPath);
        if (!is_file($configLocalPath)) {
            return null;
        }
        $owner = fileowner($configLocalPath);
        return $owner === false || $owner !== $effectiveUid
            ? 'Runtime user must match the owner of yourshield/config.local.php.'
            : null;
    }

    public static function canonicalHost(string $raw): string
    {
        $host = strtolower(trim($raw));
        if ($host === '' || str_contains($host, "\0") || preg_match('~[\\s/@?#]~', $host)) {
            return '';
        }

        if ($host[0] === '[') {
            if (!preg_match('/^\[([^]]+)](?::([0-9]{1,5}))?$/', $host, $match)) {
                return '';
            }
            if (isset($match[2]) && ((int) $match[2] < 1 || (int) $match[2] > 65535)) {
                return '';
            }
            return filter_var($match[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? $match[1] : '';
        }

        if (substr_count($host, ':') === 1) {
            [$candidate, $port] = explode(':', $host, 2);
            if ($port === '' || !ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
                return '';
            }
            $host = $candidate;
        } elseif (str_contains($host, ':')) {
            return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? $host : '';
        }

        $host = rtrim($host, '.');
        if ($host === '' || strlen($host) > 253) {
            return '';
        }
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $host;
        }

        return preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $host)
            ? $host
            : '';
    }

    public static function resolveSiteHost(array $server, string $configured = '', ?string $environment = null): string
    {
        $environment ??= (string) (getenv('YS_SITE_HOST') ?: '');
        foreach ([$server['HTTP_HOST'] ?? '', $configured, $environment, $server['SERVER_NAME'] ?? ''] as $candidate) {
            $host = self::canonicalHost(is_string($candidate) ? $candidate : '');
            if ($host !== '') {
                return $host;
            }
        }
        return '';
    }

    public static function resolvePhpCli(string $configured = ''): ?string
    {
        if (!self::canUseExec()) {
            return null;
        }

        $candidates = [
            $configured,
            defined('PHP_BINDIR') ? PHP_BINDIR . '/php' : '',
            defined('PHP_BINARY') && is_string(PHP_BINARY) ? PHP_BINARY : '',
            '/usr/bin/php',
            '/usr/local/bin/php',
            'php',
        ];

        foreach (array_unique(array_filter(array_map('trim', $candidates))) as $candidate) {
            $name = strtolower(basename($candidate));
            if (str_contains($name, 'fpm') || str_contains($name, 'cgi')) {
                continue;
            }

            try {
                $output = [];
                $code = 1;
                @exec(self::buildPhpCliProbeCommand($candidate), $output, $code);
                if ($code === 0) {
                    return $candidate;
                }
            } catch (\Throwable) {
                return null;
            }
        }

        return null;
    }

    public static function lintPhpFile(string $path, string $configuredPhp = ''): bool
    {
        $php = self::resolvePhpCli($configuredPhp);
        if ($php === null) {
            return false;
        }

        try {
            $output = [];
            $code = 1;
            @exec(self::buildPhpLintCommand($php, $path), $output, $code);
            return $code === 0;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function buildPhpCliProbeCommand(string $php, ?bool $windows = null): string
    {
        return escapeshellarg($php)
            . ' -r ' . escapeshellarg('exit(PHP_SAPI === "cli" ? 0 : 1);')
            . self::discardOutputRedirect($windows);
    }

    public static function buildPhpLintCommand(string $php, string $path, ?bool $windows = null): string
    {
        return escapeshellarg($php) . ' -l ' . escapeshellarg($path) . self::discardOutputRedirect($windows);
    }

    private static function discardOutputRedirect(?bool $windows): string
    {
        $windows ??= DIRECTORY_SEPARATOR === '\\';
        return $windows ? ' >NUL 2>&1' : ' >/dev/null 2>&1';
    }

    private static function canUseExec(): bool
    {
        if (!function_exists('exec')) {
            return false;
        }

        $disabled = strtolower((string) ini_get('disable_functions'));
        return $disabled === '' || !in_array('exec', array_map('trim', explode(',', $disabled)), true);
    }

    public static function pathMatchesPrefix(string $path, string $prefix): bool
    {
        $prefix = '/' . ltrim(trim($prefix), '/');
        $prefix = rtrim($prefix, '/');
        if ($prefix === '') {
            $prefix = '/';
        }
        return $prefix === '/' || $path === $prefix || str_starts_with($path, $prefix . '/');
    }

    public static function normalizePath(string $uri): string
    {
        $path = parse_url($uri, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return '/';
        }
        return '/' . ltrim($path, '/');
    }

    public static function fullUrl(array $server, array $trustedProxyCfg = []): string
    {
        $host = $server['HTTP_HOST'] ?? ($server['SERVER_NAME'] ?? 'localhost');
        $scheme = self::requestScheme($server, $trustedProxyCfg);
        $requestUri = $server['REQUEST_URI'] ?? '/';
        return $scheme . '://' . $host . $requestUri;
    }

    public static function requestTarget(array $server): string
    {
        $requestUri = (string) ($server['REQUEST_URI'] ?? '/');
        $decodedPath = rawurldecode(explode('?', $requestUri, 2)[0]);
        if ($requestUri === '' || $requestUri[0] !== '/'
            || str_starts_with($decodedPath, '//')
            || str_contains($decodedPath, '\\')
            || preg_match('/[\x00-\x20\x7f]/', $requestUri)
            || preg_match('/[\x00-\x1f\x7f]/', $decodedPath)
        ) {
            return '/';
        }
        return $requestUri;
    }

    public static function requestScheme(array $server, array $trustedProxyCfg = []): string
    {
        $remoteIp = self::normalizeIp((string) ($server['REMOTE_ADDR'] ?? '0.0.0.0'));
        if (self::isTrustedProxyRequest($remoteIp, $trustedProxyCfg)) {
            $protoHeader = self::trustedHeaderName($trustedProxyCfg['proto_header'] ?? null, 'HTTP_X_FORWARDED_PROTO');
            $forwardedProto = strtolower((string) ($server[$protoHeader] ?? ''));
            if ($forwardedProto !== '') {
                $parts = explode(',', $forwardedProto);
                $candidate = strtolower(trim((string) ($parts[0] ?? '')));
                if ($candidate === 'http' || $candidate === 'https') {
                    return $candidate;
                }
            }
        }

        $https = strtolower((string) ($server['HTTPS'] ?? ''));
        if ($https !== '' && $https !== 'off') {
            return 'https';
        }

        if ((string) ($server['SERVER_PORT'] ?? '') === '443') {
            return 'https';
        }

        return 'http';
    }

    public static function clientIp(array $server, array $trustedProxyCfg = []): string
    {
        $remoteIp = self::normalizeIp((string) ($server['REMOTE_ADDR'] ?? '0.0.0.0'));
        if (filter_var($remoteIp, FILTER_VALIDATE_IP) === false) {
            $remoteIp = '0.0.0.0';
        }

        if (!self::isTrustedProxyRequest($remoteIp, $trustedProxyCfg)) {
            return $remoteIp;
        }

        $ipHeader = self::trustedHeaderName($trustedProxyCfg['ip_header'] ?? null, 'HTTP_X_FORWARDED_FOR');
        $forwardedFor = (string) ($server[$ipHeader] ?? '');
        if ($forwardedFor === '') {
            return $remoteIp;
        }

        $trustedCidrs = self::sanitizeCidrs($trustedProxyCfg['trusted_cidrs'] ?? []);
        $forwardedIps = self::parseForwardedFor($forwardedFor);
        if ($forwardedIps === []) {
            return $remoteIp;
        }

        foreach (array_reverse($forwardedIps) as $candidate) {
            if (!self::ipInCidrs($candidate, $trustedCidrs)) {
                return $candidate;
            }
        }

        return $forwardedIps[0];
    }

    public static function isPathUnderBase(string $path, string $basePath): bool
    {
        if ($path === $basePath) {
            return true;
        }
        return str_starts_with($path, $basePath . '/');
    }

    public static function relativeToBase(string $path, string $basePath): string
    {
        if (!self::isPathUnderBase($path, $basePath)) {
            return $path;
        }

        $relative = substr($path, strlen($basePath));
        if ($relative === false || $relative === '') {
            return '/';
        }

        return '/' . ltrim($relative, '/');
    }

    public static function normalizeRoutePath(string $routePath, string $basePath): string
    {
        $route = '/' . ltrim($routePath, '/');
        if (self::isPathUnderBase($route, $basePath)) {
            return self::relativeToBase($route, $basePath);
        }
        return $route;
    }

    public static function joinBaseAndRoute(string $basePath, string $routePath): string
    {
        $route = '/' . ltrim($routePath, '/');
        return rtrim($basePath, '/') . $route;
    }

    public static function appendQueryParam(string $url, string $name, string $value): string
    {
        $parts = parse_url($url);
        if ($parts === false) {
            return $url;
        }

        $query = [];
        if (isset($parts['query'])) {
            parse_str($parts['query'], $query);
        }
        $query[$name] = $value;

        $rebuilt = '';
        if (isset($parts['scheme'])) {
            $rebuilt .= $parts['scheme'] . '://';
        }
        if (isset($parts['user'])) {
            $rebuilt .= $parts['user'];
            if (isset($parts['pass'])) {
                $rebuilt .= ':' . $parts['pass'];
            }
            $rebuilt .= '@';
        }
        if (isset($parts['host'])) {
            $rebuilt .= $parts['host'];
        }
        if (isset($parts['port'])) {
            $rebuilt .= ':' . $parts['port'];
        }
        $rebuilt .= $parts['path'] ?? '/';
        $rebuilt .= '?' . http_build_query($query);
        if (isset($parts['fragment'])) {
            $rebuilt .= '#' . $parts['fragment'];
        }

        return $rebuilt;
    }

    public static function removeQueryParam(string $url, string $name): string
    {
        $parts = parse_url($url);
        if ($parts === false) {
            return $url;
        }

        $query = [];
        if (isset($parts['query'])) {
            parse_str($parts['query'], $query);
        }
        unset($query[$name]);

        $rebuilt = '';
        if (isset($parts['scheme'])) {
            $rebuilt .= $parts['scheme'] . '://';
        }
        if (isset($parts['user'])) {
            $rebuilt .= $parts['user'];
            if (isset($parts['pass'])) {
                $rebuilt .= ':' . $parts['pass'];
            }
            $rebuilt .= '@';
        }
        if (isset($parts['host'])) {
            $rebuilt .= $parts['host'];
        }
        if (isset($parts['port'])) {
            $rebuilt .= ':' . $parts['port'];
        }
        $rebuilt .= $parts['path'] ?? '/';
        if ($query !== []) {
            $rebuilt .= '?' . http_build_query($query);
        }
        if (isset($parts['fragment'])) {
            $rebuilt .= '#' . $parts['fragment'];
        }

        return $rebuilt;
    }

    public static function randomToken(int $length = 24): string
    {
        $bytes = random_bytes((int) ceil($length * 0.75));
        $token = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        return substr($token, 0, $length);
    }

    public static function normalizeUserAgent(string $ua): string
    {
        $ua = strtolower(trim($ua));
        $ua = preg_replace('/\s+/', ' ', $ua) ?? $ua;
        return substr($ua, 0, 180);
    }

    public static function fingerprint(array $server, array $trustedProxyCfg = []): string
    {
        $ip = self::clientIp($server, $trustedProxyCfg);
        $ua = self::normalizeUserAgent((string) ($server['HTTP_USER_AGENT'] ?? ''));
        $lang = strtolower((string) ($server['HTTP_ACCEPT_LANGUAGE'] ?? ''));
        $host = strtolower((string) ($server['HTTP_HOST'] ?? ''));
        return hash('sha256', implode('|', [$ip, $ua, $lang, $host]));
    }

    public static function readRequestBody(int $maxBytes, ?array $server = null): ?string
    {
        $maxBytes = max(0, $maxBytes);
        $server ??= $_SERVER;
        if (array_key_exists('CONTENT_LENGTH', $server)) {
            $contentLengthRaw = trim((string) $server['CONTENT_LENGTH']);
            if (preg_match('/\A(?:0|[1-9][0-9]*)\z/', $contentLengthRaw) !== 1) {
                return null;
            }
            $contentLength = filter_var(
                $contentLengthRaw,
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 0]]
            );
            if ($contentLength === false || $contentLength > $maxBytes) {
                return null;
            }
        }

        $stream = fopen('php://input', 'rb');
        if ($stream === false) {
            return null;
        }
        try {
            $raw = stream_get_contents($stream, $maxBytes + 1);
        } finally {
            fclose($stream);
        }
        if (!is_string($raw) || strlen($raw) > $maxBytes) {
            return null;
        }

        return $raw;
    }

    public static function isHtmlRequest(array $server): bool
    {
        $method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET'));
        if ($method !== 'GET' && $method !== 'HEAD') {
            return false;
        }

        $path = strtolower(self::normalizePath((string) ($server['REQUEST_URI'] ?? '/')));
        $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        if ($extension !== '' && in_array($extension, [
            'css', 'js', 'mjs', 'map', 'json', 'xml', 'txt',
            'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico',
            'woff', 'woff2', 'ttf', 'otf', 'eot',
            'pdf', 'zip', 'gz', 'br',
        ], true)) {
            return false;
        }

        // Accept is client-controlled and cannot exempt an application route from protection.
        return true;
    }

    public static function isDocumentNavigation(array $server): bool
    {
        if (strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')) !== 'GET') {
            return false;
        }
        $destination = strtolower((string) ($server['HTTP_SEC_FETCH_DEST'] ?? ''));
        $mode = strtolower((string) ($server['HTTP_SEC_FETCH_MODE'] ?? ''));
        if ($destination !== '' || $mode !== '') {
            return $destination === 'document' && $mode === 'navigate';
        }
        if (strtolower((string) ($server['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest') {
            return false;
        }
        $accept = strtolower((string) ($server['HTTP_ACCEPT'] ?? ''));
        return $accept === '' || str_contains($accept, 'text/html');
    }

    public static function sameOrigin(array $server, string $headerUrl, array $trustedProxyCfg = []): bool
    {
        $hostHeader = strtolower((string) ($server['HTTP_HOST'] ?? ''));
        if ($hostHeader === '') {
            return true;
        }

        $scheme = self::requestScheme($server, $trustedProxyCfg);
        $currentHost = parse_url('http://' . $hostHeader, PHP_URL_HOST);
        if (!is_string($currentHost) || $currentHost === '') {
            $currentHost = $hostHeader;
        }
        $currentHost = strtolower($currentHost);

        $hostPort = parse_url('http://' . $hostHeader, PHP_URL_PORT);
        $currentPort = $hostPort !== null && $hostPort !== false
            ? (string) $hostPort
            : ($scheme === 'https' ? '443' : '80');

        $parts = parse_url($headerUrl);
        if ($parts === false || !isset($parts['host'])) {
            return false;
        }

        $originHost = strtolower((string) $parts['host']);
        $originScheme = strtolower((string) ($parts['scheme'] ?? $scheme));
        $originPort = (string) ($parts['port'] ?? ($originScheme === 'https' ? '443' : '80'));

        return $originHost === $currentHost && $originScheme === $scheme && $originPort === $currentPort;
    }

    public static function sanitizePathNoQuery(string $path): string
    {
        $normalized = self::normalizePath($path);
        return preg_replace('/[^\w\-\/\.]/', '', $normalized) ?? '/';
    }

    public static function validateCloudBaseUrl(string $url, array $policy = []): ?string
    {
        $url = trim($url);
        if ($url === '') {
            return 'cloud_base_url_empty';
        }

        $parts = parse_url($url);
        if ($parts === false) {
            return 'cloud_base_url_invalid';
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if ($scheme !== 'http' && $scheme !== 'https') {
            return 'cloud_base_url_scheme_invalid';
        }

        $allowHttp = (bool) ($policy['allow_http'] ?? false);
        if ($scheme === 'http' && !$allowHttp) {
            return 'cloud_base_url_http_not_allowed';
        }

        $host = strtolower((string) ($parts['host'] ?? ''));
        if ($host === '') {
            return 'cloud_base_url_host_missing';
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            return 'cloud_base_url_userinfo_forbidden';
        }

        if (isset($parts['fragment']) && (string) $parts['fragment'] !== '') {
            return 'cloud_base_url_fragment_forbidden';
        }

        if (!self::isAllowedHost($host, $policy['allowed_hosts'] ?? [])) {
            return 'cloud_base_url_host_not_allowed';
        }

        $allowLocalhost = (bool) ($policy['allow_localhost'] ?? false);
        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return $allowLocalhost ? null : 'cloud_base_url_localhost_not_allowed';
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $allowPrivateNetworks = (bool) ($policy['allow_private_networks'] ?? false);
            if (!$allowPrivateNetworks && self::isPrivateOrReservedIp($host)) {
                if ($allowLocalhost && self::isLoopbackIp($host)) {
                    return null;
                }
                return 'cloud_base_url_private_ip_not_allowed';
            }
        }

        return null;
    }

    public static function redactSecrets(string $message, array $knownSecrets = []): string
    {
        $out = $message;

        $patterns = [
            '/([?&](?:token|secret|password|api[_-]?key|site[_-]?key)=)([^&\s]+)/i' => '$1[REDACTED]',
            '/("(?:token|secret|password|api[_-]?key|site[_-]?key)"\s*:\s*")([^"]+)(")/i' => '$1[REDACTED]$3',
            '/\b(authorization\s*:\s*bearer\s+)([a-z0-9\-._~+\/=]+)\b/i' => '$1[REDACTED]',
            '/\b(x-ys-signature\s*:\s*)([a-f0-9]{16,})\b/i' => '$1[REDACTED]',
            '/\b((?:token|secret|password|api[_-]?key|site[_-]?key)\s*[:=]\s*)([^\s,;]+)/i' => '$1[REDACTED]',
        ];
        foreach ($patterns as $pattern => $replace) {
            $out = preg_replace($pattern, $replace, $out) ?? $out;
        }

        foreach ($knownSecrets as $secret) {
            if (!is_string($secret)) {
                continue;
            }
            $secret = trim($secret);
            if ($secret === '' || strlen($secret) < 4) {
                continue;
            }
            $out = str_replace($secret, '[REDACTED]', $out);
        }

        return $out;
    }

    public static function verifyBundleSignature(
        array $bundle,
        string $kind,
        string $key,
        int $maxAgeSec = 1800
    ): bool {
        $signature = trim((string) ($bundle['sig'] ?? ''));
        if ($signature === '' || !preg_match('/^[a-f0-9]{64}$/i', $signature)) {
            return false;
        }

        $algo = strtolower(trim((string) ($bundle['sig_alg'] ?? 'hmac-sha256')));
        if ($algo !== 'hmac-sha256') {
            return false;
        }

        $tsRaw = $bundle['sig_ts'] ?? null;
        if ($maxAgeSec > 0) {
            if (
                (!is_int($tsRaw) && (!is_string($tsRaw) || preg_match('/\A[1-9][0-9]*\z/', $tsRaw) !== 1))
                || ($sigTs = filter_var($tsRaw, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]])) === false
            ) {
                return false;
            }
            $now = time();
            if ($sigTs > ($now + 300)) {
                return false;
            }
            if (($now - $sigTs) > $maxAgeSec) {
                return false;
            }
        } else {
            $sigTs = is_numeric($tsRaw) ? (int) $tsRaw : 0;
        }

        $canonicalPayload = self::bundleCanonicalPayload($bundle);
        $canonicalJson = self::canonicalJson($canonicalPayload);
        $canonical = $kind . "\n" . $sigTs . "\n" . $canonicalJson;
        $expected = hash_hmac('sha256', $canonical, $key);
        return hash_equals(strtolower($expected), strtolower($signature));
    }

    public static function signBundle(
        array $bundle,
        string $kind,
        string $key,
        ?int $timestamp = null
    ): array {
        $sigTs = $timestamp ?? time();
        $unsigned = self::bundleCanonicalPayload($bundle);
        $canonicalJson = self::canonicalJson($unsigned);
        $canonical = $kind . "\n" . $sigTs . "\n" . $canonicalJson;
        $signature = hash_hmac('sha256', $canonical, $key);

        $unsigned['sig_alg'] = 'hmac-sha256';
        $unsigned['sig_ts'] = $sigTs;
        $unsigned['sig'] = $signature;
        return $unsigned;
    }

    public static function canonicalJson(mixed $value): string
    {
        $normalized = self::sortRecursive($value);
        $json = json_encode($normalized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return is_string($json) ? $json : 'null';
    }

    public static function bundleCanonicalPayload(array $bundle): array
    {
        unset($bundle['sig'], $bundle['sig_alg'], $bundle['sig_ts']);
        return $bundle;
    }

    private static function trustedHeaderName(mixed $value, string $fallback): string
    {
        if (!is_string($value) || trim($value) === '') {
            return $fallback;
        }

        $name = strtoupper(trim($value));
        $name = str_replace('-', '_', $name);
        if (!str_starts_with($name, 'HTTP_') && $name !== 'REMOTE_ADDR') {
            $name = 'HTTP_' . $name;
        }

        return $name;
    }

    private static function isTrustedProxyRequest(string $remoteIp, array $trustedProxyCfg): bool
    {
        $enabled = (bool) ($trustedProxyCfg['enabled'] ?? false);
        if (!$enabled) {
            return false;
        }

        if (filter_var($remoteIp, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $cidrs = self::sanitizeCidrs($trustedProxyCfg['trusted_cidrs'] ?? []);
        if ($cidrs === []) {
            return false;
        }

        return self::ipInCidrs($remoteIp, $cidrs);
    }

    private static function parseForwardedFor(string $headerValue): array
    {
        $parts = explode(',', $headerValue);
        $ips = [];

        foreach ($parts as $part) {
            $candidate = self::normalizeIp((string) $part);
            if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                $ips[] = $candidate;
            }
        }

        return $ips;
    }

    private static function normalizeIp(string $raw): string
    {
        $raw = trim($raw);
        if ($raw === '') {
            return '0.0.0.0';
        }

        if (str_starts_with($raw, '[')) {
            $end = strpos($raw, ']');
            if ($end !== false) {
                $raw = substr($raw, 1, $end - 1);
            }
        } else {
            if (substr_count($raw, ':') === 1 && str_contains($raw, '.')) {
                [$host, $port] = explode(':', $raw, 2);
                if (
                    filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
                    && ctype_digit($port)
                ) {
                    $raw = $host;
                }
            }
        }

        $zonePos = strpos($raw, '%');
        if ($zonePos !== false) {
            $raw = substr($raw, 0, $zonePos);
        }

        return trim($raw);
    }

    private static function sanitizeCidrs(mixed $cidrs): array
    {
        if (is_string($cidrs)) {
            $cidrs = explode(',', $cidrs);
        }
        if (!is_array($cidrs)) {
            return [];
        }

        $out = [];
        foreach ($cidrs as $cidr) {
            if (!is_string($cidr)) {
                continue;
            }
            $cidr = trim($cidr);
            if ($cidr === '') {
                continue;
            }
            if (!str_contains($cidr, '/')) {
                if (filter_var($cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                    $cidr .= '/32';
                } elseif (filter_var($cidr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                    $cidr .= '/128';
                } else {
                    continue;
                }
            }
            $out[] = $cidr;
        }

        return array_values(array_unique($out));
    }

    private static function ipInCidrs(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::ipInCidr($ip, (string) $cidr)) {
                return true;
            }
        }
        return false;
    }

    private static function ipInCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return false;
        }

        [$subnet, $prefixRaw] = explode('/', $cidr, 2);
        $subnet = trim($subnet);
        if ($subnet === '' || $prefixRaw === '' || !is_numeric($prefixRaw)) {
            return false;
        }

        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false) {
            return false;
        }
        if (strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $prefix = (int) $prefixRaw;
        $maxBits = strlen($ipBin) * 8;
        if ($prefix < 0 || $prefix > $maxBits) {
            return false;
        }

        $fullBytes = intdiv($prefix, 8);
        $remainingBits = $prefix % 8;

        if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
        $ipByte = ord($ipBin[$fullBytes]);
        $subnetByte = ord($subnetBin[$fullBytes]);

        return ($ipByte & $mask) === ($subnetByte & $mask);
    }

    private static function isAllowedHost(string $host, mixed $allowedHosts): bool
    {
        if (is_string($allowedHosts)) {
            $allowedHosts = explode(',', $allowedHosts);
        }
        if (!is_array($allowedHosts) || $allowedHosts === []) {
            return true;
        }

        $host = strtolower(trim($host));
        foreach ($allowedHosts as $rule) {
            if (!is_string($rule)) {
                continue;
            }
            $rule = strtolower(trim($rule));
            if ($rule === '') {
                continue;
            }

            if ($host === $rule) {
                return true;
            }

            if (str_starts_with($rule, '*.')) {
                $suffix = substr($rule, 1);
                if ($suffix !== '' && str_ends_with($host, $suffix)) {
                    return true;
                }
            }

            if (str_starts_with($rule, '.')) {
                if (str_ends_with($host, $rule)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static function isPrivateOrReservedIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    private static function isLoopbackIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return str_starts_with($ip, '127.');
        }

        $bin = inet_pton($ip);
        $loop = inet_pton('::1');
        return $bin !== false && $loop !== false && hash_equals($bin, $loop);
    }

    private static function sortRecursive(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        $isList = array_keys($value) === range(0, count($value) - 1);
        if ($isList) {
            $out = [];
            foreach ($value as $item) {
                $out[] = self::sortRecursive($item);
            }
            return $out;
        }

        $copy = $value;
        ksort($copy);
        foreach ($copy as $k => $v) {
            $copy[$k] = self::sortRecursive($v);
        }
        return $copy;
    }
}
