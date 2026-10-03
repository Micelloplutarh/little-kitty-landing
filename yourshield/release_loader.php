<?php
declare(strict_types=1);

/**
 * Read the canonical code inventory required before an immutable release can serve traffic.
 *
 * @return list<string>|null
 */
function ys_required_module_release_files(string $moduleRoot): ?array
{
    $inventoryPath = rtrim($moduleRoot, '/\\') . '/release-required.txt';
    if (!is_file($inventoryPath) || is_link($inventoryPath)) {
        return null;
    }
    $raw = @file_get_contents($inventoryPath);
    if (!is_string($raw) || $raw === '' || strlen($raw) > 16384 || !str_ends_with($raw, "\n")) {
        return null;
    }

    $files = [];
    $caseFolded = [];
    foreach (explode("\n", $raw) as $line) {
        $relative = trim($line);
        if ($relative === '') {
            continue;
        }
        if ($relative[0] === '/'
            || str_contains($relative, '\\')
            || preg_match('/[\x00-\x1F\x7F:]/', $relative)
        ) {
            return null;
        }
        foreach (explode('/', $relative) as $part) {
            if ($part === '' || $part === '.' || $part === '..') {
                return null;
            }
        }
        $folded = strtolower($relative);
        if (isset($caseFolded[$folded])) {
            return null;
        }
        $caseFolded[$folded] = true;
        $files[] = $relative;
    }
    return in_array('release-required.txt', $files, true) ? $files : null;
}

function ys_module_release_is_complete(string $candidate, string $releaseId): bool
{
    if (!is_dir($candidate) || is_link($candidate)) {
        return false;
    }
    $libDir = $candidate . '/lib';
    if (!is_dir($libDir) || is_link($libDir)) {
        return false;
    }
    $requiredFiles = ys_required_module_release_files($candidate);
    if ($requiredFiles === null) {
        return false;
    }
    foreach ($requiredFiles as $relative) {
        $path = $candidate . '/' . $relative;
        if (!is_file($path) || is_link($path)) {
            return false;
        }
    }

    $completePath = $candidate . '/.release-complete';
    if (!is_file($completePath) || is_link($completePath)) {
        return false;
    }
    $complete = @file_get_contents($completePath);
    return is_string($complete) && trim($complete) === $releaseId;
}

/**
 * Return the last fully committed release id from an already-read pointer journal.
 *
 * The journal is append-only. An unterminated final line is deliberately ignored,
 * so a process crash during append can only leave the previous release active.
 */
function ys_last_module_release_id(string $journal, string $moduleRoot): ?string
{
    $lastNewline = strrpos($journal, "\n");
    if ($lastNewline === false) {
        return null;
    }

    $completeJournal = substr($journal, 0, $lastNewline + 1);
    $entries = explode("\n", $completeJournal);
    for ($i = count($entries) - 1; $i >= 0; $i--) {
        $releaseId = trim($entries[$i]);
        if (!preg_match('/\Ar-[a-f0-9]{64}\z/', $releaseId)) {
            continue;
        }

        $candidate = $moduleRoot . '/.module-releases/' . $releaseId;
        if (ys_module_release_is_complete($candidate, $releaseId)) {
            return $releaseId;
        }
    }

    return null;
}

/**
 * Resolve and pin one coherent module tree before config/autoload are evaluated.
 */
function ys_resolve_module_release_root(string $moduleRoot): string
{
    $moduleRoot = rtrim($moduleRoot, '/\\');
    $pointerPath = $moduleRoot . '/.module-current';
    clearstatcache(true, $pointerPath);
    if ((file_exists($pointerPath) || is_link($pointerPath))
        && (is_link($pointerPath) || !is_file($pointerPath))
    ) {
        return $moduleRoot;
    }
    $pointer = @fopen($pointerPath, 'rb');
    if (!is_resource($pointer)) {
        return $moduleRoot;
    }

    $journal = null;
    if (flock($pointer, LOCK_SH)) {
        $journal = stream_get_contents($pointer);
        flock($pointer, LOCK_UN);
    }
    fclose($pointer);

    if (!is_string($journal)) {
        return $moduleRoot;
    }

    $releaseId = ys_last_module_release_id($journal, $moduleRoot);
    return $releaseId === null
        ? $moduleRoot
        : $moduleRoot . '/.module-releases/' . $releaseId;
}
