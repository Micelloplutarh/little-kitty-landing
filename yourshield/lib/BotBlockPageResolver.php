<?php
declare(strict_types=1);

namespace YourShield;

final class BotBlockPageResolver
{
    public static function resolve(RuntimeConfig $config, string $seed = ''): ?array
    {
        $botBlockCfg = $config->getArray('bot_blocking');
        $mode = strtolower(trim((string) ($botBlockCfg['mode'] ?? 'block')));
        if ($mode !== 'whitepage_dir') {
            return null;
        }

        $directory = self::normalizeDirectory((string) ($botBlockCfg['whitepage_dir'] ?? ''));
        if ($directory === null) {
            return null;
        }

        $files = self::collectFiles($config->getString('public_root'), $directory);
        $selected = self::selectFile($files, $seed);
        if ($selected === null) {
            return null;
        }

        $html = file_get_contents($selected);
        if (!is_string($html) || trim($html) === '') {
            return null;
        }
        $html = self::applyVirtualRoot($html, $directory);

        return [
            'html' => $html,
            'file' => $selected,
            'directory' => $directory,
        ];
    }

    public static function normalizeDirectory(string $raw): ?string
    {
        $raw = trim(str_replace('\\', '/', $raw));
        if ($raw === '' || str_contains($raw, "\0")) {
            return null;
        }

        $parts = explode('/', $raw);
        $normalized = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                return null;
            }
            $normalized[] = $part;
        }

        if ($normalized === []) {
            return null;
        }

        return '/' . implode('/', $normalized);
    }

    public static function collectFiles(string $publicRoot, string $directory): array
    {
        $normalizedDir = self::normalizeDirectory($directory);
        if ($normalizedDir === null) {
            return [];
        }

        $publicRoot = rtrim(trim($publicRoot), '/');
        if ($publicRoot === '' || !is_dir($publicRoot)) {
            return [];
        }

        $targetDir = $publicRoot . '/' . ltrim($normalizedDir, '/');
        if (!is_dir($targetDir)) {
            return [];
        }

        $files = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($targetDir, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $entry) {
                if (!$entry instanceof \SplFileInfo || !$entry->isFile()) {
                    continue;
                }
                $ext = strtolower($entry->getExtension());
                if ($ext !== 'html' && $ext !== 'htm') {
                    continue;
                }
                $files[] = $entry->getPathname();
            }
        } catch (\Throwable) {
            return [];
        }

        sort($files, SORT_STRING);
        return $files;
    }

    private static function selectFile(array $files, string $seed): ?string
    {
        if ($files === []) {
            return null;
        }

        $count = count($files);
        if ($count === 1) {
            return (string) $files[0];
        }

        if ($seed !== '') {
            $seedHash = (int) sprintf('%u', crc32($seed));
            $index = $seedHash % $count;
            return (string) $files[$index];
        }

        return (string) $files[random_int(0, $count - 1)];
    }

    private static function applyVirtualRoot(string $html, string $directory): string
    {
        $directory = self::normalizeDirectory($directory) ?? '';
        if ($directory === '') {
            return $html;
        }

        $result = self::injectBaseHref($html, $directory);
        $result = self::rewriteUrlAttributes($result, $directory);
        $result = self::rewriteSrcsetAttributes($result, $directory);
        $result = self::rewriteInlineCssUrls($result, $directory);
        return $result;
    }

    private static function injectBaseHref(string $html, string $directory): string
    {
        if (preg_match('/<base\s[^>]*href\s*=/i', $html) === 1) {
            return $html;
        }

        $baseTag = '<base href="' . htmlspecialchars(rtrim($directory, '/') . '/', ENT_QUOTES, 'UTF-8') . '">';
        $replaced = preg_replace('/<head\b[^>]*>/i', '$0' . $baseTag, $html, 1);
        if (is_string($replaced) && $replaced !== '') {
            return $replaced;
        }
        return $baseTag . $html;
    }

    private static function rewriteUrlAttributes(string $html, string $directory): string
    {
        $pattern = '/\b(href|src|action|poster|data)\s*=\s*(["\'])([^"\']*)\2/i';
        $rewritten = preg_replace_callback($pattern, static function (array $m) use ($directory): string {
            $value = (string) ($m[3] ?? '');
            $newValue = self::rewritePathToken($value, $directory);
            return (string) ($m[1] ?? '') . '=' . (string) ($m[2] ?? '"') . $newValue . (string) ($m[2] ?? '"');
        }, $html);

        return is_string($rewritten) ? $rewritten : $html;
    }

    private static function rewriteSrcsetAttributes(string $html, string $directory): string
    {
        $pattern = '/\bsrcset\s*=\s*(["\'])([^"\']*)\1/i';
        $rewritten = preg_replace_callback($pattern, static function (array $m) use ($directory): string {
            $value = (string) ($m[2] ?? '');
            $parts = explode(',', $value);
            $out = [];
            foreach ($parts as $part) {
                $segment = trim($part);
                if ($segment === '') {
                    continue;
                }
                $tokens = preg_split('/\s+/', $segment, 2) ?: [];
                $url = (string) ($tokens[0] ?? '');
                $descriptor = (string) ($tokens[1] ?? '');
                $rewrittenUrl = self::rewritePathToken($url, $directory);
                $out[] = $descriptor !== '' ? ($rewrittenUrl . ' ' . $descriptor) : $rewrittenUrl;
            }
            $joined = implode(', ', $out);
            return 'srcset=' . (string) ($m[1] ?? '"') . $joined . (string) ($m[1] ?? '"');
        }, $html);

        return is_string($rewritten) ? $rewritten : $html;
    }

    private static function rewriteInlineCssUrls(string $html, string $directory): string
    {
        $pattern = '/url\(\s*(["\']?)(\/[^)\'"]*)\1\s*\)/i';
        $rewritten = preg_replace_callback($pattern, static function (array $m) use ($directory): string {
            $quote = (string) ($m[1] ?? '');
            $path = (string) ($m[2] ?? '');
            $newPath = self::rewritePathToken($path, $directory);
            return 'url(' . $quote . $newPath . $quote . ')';
        }, $html);

        return is_string($rewritten) ? $rewritten : $html;
    }

    private static function rewritePathToken(string $value, string $directory): string
    {
        $trimmed = trim($value);
        if ($trimmed === '') {
            return $value;
        }
        if ($trimmed[0] !== '/') {
            return $value;
        }
        if (str_starts_with($trimmed, '//')) {
            return $value;
        }
        if (self::hasUriScheme($trimmed)) {
            return $value;
        }

        $prefix = rtrim($directory, '/');
        if ($trimmed === $prefix || str_starts_with($trimmed, $prefix . '/')) {
            return $value;
        }
        if ($trimmed === '/') {
            return $prefix . '/';
        }
        return $prefix . $trimmed;
    }

    private static function hasUriScheme(string $value): bool
    {
        return preg_match('/^[a-z][a-z0-9+\-.]*:/i', $value) === 1;
    }
}
