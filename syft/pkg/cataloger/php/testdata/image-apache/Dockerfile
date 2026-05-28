FROM --platform=linux/amd64 httpd:2.4.63-bookworm AS builder

# pin php8.2 packages to avoid version drift when debian publishes security updates
ARG PHP_VERSION=8.2.31-1~deb12u1
RUN apt update -y && apt install -y \
    libapache2-mod-php8.2=${PHP_VERSION} \
    php8.2-common=${PHP_VERSION} \
    php8.2-xml=${PHP_VERSION} \
    php8.2-mysql=${PHP_VERSION} \
    php8.2-opcache=${PHP_VERSION}

FROM busybox:latest

# phplib.so
COPY --from=builder /usr/lib/apache2/ /usr/lib/apache2/

# php extensions
COPY --from=builder /usr/lib/php/ /usr/lib/php/
