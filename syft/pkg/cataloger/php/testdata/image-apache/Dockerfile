FROM --platform=linux/amd64 httpd:2.4.63-bookworm AS builder

RUN apt update -y && apt install -y libapache2-mod-php php8.2-memcache php8.2-memcache php8.2-xml php8.2-mysqli php8.2-opcache

FROM busybox:latest

# phplib.so
COPY --from=builder /usr/lib/apache2/ /usr/lib/apache2/

# php extensions
COPY --from=builder /usr/lib/php/ /usr/lib/php/
