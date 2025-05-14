# source https://github.com/nextcloud/docker/blob/master/30/fpm-alpine/Dockerfile#L1
FROM --platform=linux/amd64 php:8.3-fpm-alpine3.21 AS builder

# entrypoint.sh and cron.sh dependencies
RUN set -ex; \
    \
    apk add --no-cache \
    imagemagick \
    imagemagick-pdf \
    imagemagick-jpeg \
    imagemagick-raw \
    imagemagick-tiff \
    imagemagick-heic \
    imagemagick-webp \
    imagemagick-svg \
    rsync \
    ; \
    \
    rm /var/spool/cron/crontabs/root; \
    echo '*/5 * * * * php -f /var/www/html/cron.php' > /var/spool/cron/crontabs/www-data

# install the PHP extensions we need
# see https://docs.nextcloud.com/server/stable/admin_manual/installation/source_installation.html
RUN set -ex; \
    \
    apk add --no-cache --virtual .build-deps \
    $PHPIZE_DEPS \
    autoconf \
    freetype-dev \
    gmp-dev \
    icu-dev \
    imagemagick-dev \
    libevent-dev \
    libjpeg-turbo-dev \
    libmcrypt-dev \
    libmemcached-dev \
    libpng-dev \
    libwebp-dev \
    libxml2-dev \
    libzip-dev \
    openldap-dev \
    pcre-dev \
    postgresql-dev \
    ; \
    \
    docker-php-ext-configure ftp --with-openssl-dir=/usr; \
    docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp; \
    docker-php-ext-configure ldap; \
    docker-php-ext-install -j "$(nproc)" \
    bcmath \
    exif \
    ftp \
    gd \
    gmp \
    intl \
    ldap \
    opcache \
    pcntl \
    pdo_mysql \
    pdo_pgsql \
    sysvsem \
    zip \
    ; \
    \
    # pecl will claim success even if one install fails, so we need to perform each install separately
    pecl install APCu-5.1.24; \
    pecl install igbinary-3.2.16; \
    pecl install imagick-3.8.0; \
    pecl install memcached-3.3.0 \
    --configureoptions 'enable-memcached-igbinary="yes"'; \
    pecl install redis-6.2.0 \
    --configureoptions 'enable-redis-igbinary="yes" enable-redis-zstd="yes" enable-redis-lz4="yes"'; \
    \
    docker-php-ext-enable \
    apcu \
    igbinary \
    imagick \
    memcached \
    redis \
    ; \
    rm -r /tmp/pear; \
    \
    runDeps="$( \
    scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions \
    | tr ',' '\n' \
    | sort -u \
    | awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
    )"; \
    apk add --no-network --virtual .nextcloud-phpext-rundeps $runDeps; \
    apk del --no-network .build-deps

FROM busybox:latest

# interpreters + process manager
COPY --from=builder  /usr/local/sbin/php-fpm       /usr/local/sbin/php-fpm
COPY --from=builder  /usr/local/bin/php            /usr/local/bin/php

# extensions
COPY --from=builder  /usr/local/lib/php/extensions /usr/local/lib/php/extensions

# configs
COPY --from=builder  /usr/local/etc/php-fpm.conf   /usr/local/etc/php-fpm.conf
COPY --from=builder  /usr/local/etc/php/conf.d     /usr/local/etc/php/conf.d
COPY --from=builder  /usr/local/etc/php-fpm.d      /usr/local/etc/php-fpm.d
COPY --from=builder  /usr/local/etc/php-fpm.conf   /usr/local/etc/php-fpm.conf
