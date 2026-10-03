FROM php:8.3-apache

# Расширения для YourShield: opcache, apcu/redis-кэш (curl и posix уже есть в образе)
RUN docker-php-ext-install opcache \
    && pecl install apcu redis \
    && docker-php-ext-enable apcu redis \
    && a2enmod rewrite headers

# Лендинг + PHP целиком в корень раздачи Apache
COPY . /var/www/html

# Конфиг Apache: кэш статики, закрытые служебные файлы
COPY apache.conf /etc/apache2/conf-enabled/landing.conf

# Apache работает от www-data — ему нужна запись (YourShield пишет config.local.php)
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
