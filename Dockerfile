FROM php:8.3-apache

# Расширения для YourShield: opcache, apcu/redis-кэш (curl и posix уже есть в образе)
RUN docker-php-ext-install opcache \
    && pecl install apcu redis \
    && docker-php-ext-enable apcu redis \
    && a2enmod rewrite headers

# Лендинг + PHP кладём вне volume: в /var/www/html их копирует docker-entrypoint.sh
COPY . /usr/src/landing

# Конфиг Apache: кэш статики, закрытые служебные файлы
COPY apache.conf /etc/apache2/conf-enabled/landing.conf
COPY php.ini /usr/local/etc/php/conf.d/landing.ini

COPY docker-entrypoint.sh /usr/local/bin/landing-entrypoint
ENTRYPOINT ["landing-entrypoint"]
CMD ["apache2-foreground"]

EXPOSE 80
