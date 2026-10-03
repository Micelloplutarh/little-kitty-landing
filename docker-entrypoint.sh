#!/bin/sh
set -e

# /var лежит в volume и переживает деплои: свежие файлы репозитория
# докладываем поверх, а то, что дописал YourShield, не трогаем
cd /usr/src/landing
for f in * .[!.]*; do
    [ -e "$f" ] || continue
    # модуль YourShield обновляет себя сам — в volume его не перезатираем
    [ "$f" = yourshield ] && [ -d /var/www/html/yourshield ] && continue
    cp -a "$f" /var/www/html/
done
chown -R www-data:www-data /var/www/html

cd /var/www/html
exec docker-php-entrypoint "$@"
