FROM --platform=linux/amd64 httpd:2.4.63-bookworm AS builder

# pin apt to a debian snapshot so the exact php8.2 point release stays installable.
# a plain version pin drifts out from under us: debian's mirrors only keep the latest
# point release, so 8.2.31 disappears once 8.2.32 ships. snapshot.debian.org archives
# every version forever, which is what actually keeps the fixture (and its test
# expectations) reproducible. timestamp is any point where 8.2.31 was current
# (8.2.31: 2026-05-08, 8.2.32: 2026-07-04).
ARG SNAPSHOT=20260701T000000Z
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources && \
    printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bookworm main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bookworm-updates main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bookworm-security main" \
      > /etc/apt/sources.list

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
