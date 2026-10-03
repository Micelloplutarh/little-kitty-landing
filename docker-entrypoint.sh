#!/bin/sh
set -e

# /var лежит в volume и переживает деплои: свежие файлы репозитория
# докладываем поверх, а то, что дописал YourShield, не трогаем
cd /usr/src/landing
for f in * .[!.]*; do
    [ -e "$f" ] || continue
    if [ "$f" = yourshield ]; then
        # установленный YourShield (есть config.local.php) обновляет себя сам — не перезатираем;
        # неустановленный заменяем целиком, чтобы не оставался старый setup.php
        [ -f /var/www/html/yourshield/config.local.php ] && continue
        rm -rf /var/www/html/yourshield
    fi
    cp -a "$f" /var/www/html/
done
chown -R www-data:www-data /var/www/html

cd /var/www/html
exec docker-php-entrypoint "$@"
