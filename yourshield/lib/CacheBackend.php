<?php
declare(strict_types=1);

namespace YourShield;

interface CacheBackend
{
    public function get(string $key, mixed $default = null): mixed;

    public function set(string $key, mixed $value, int $ttlSeconds): void;

    public function add(string $key, mixed $value, int $ttlSeconds): bool;

    public function delete(string $key): void;

    public function mutate(string $key, int $ttlSeconds, callable $updater, mixed $default = null): mixed;
}
