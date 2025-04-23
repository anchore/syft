FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    curl \
    xz \
    shadow \
    sudo \
    tar \
    git \
    ca-certificates \
    build-base

# create required directories and users for Nix
RUN mkdir -m 0755 /nix && \
    addgroup -g 30000 nixbld && \
    for i in $(seq 1 30); do \
        adduser -D -h /var/empty -G nixbld -u $((30000 + i)) nixbld$i ; \
    done

# install Nix
RUN curl -L https://nixos.org/nix/install | sh

# source Nix environment in shell
SHELL ["/bin/ash", "-c"]
ENV PATH="${PATH}:/root/.nix-profile/bin"
RUN echo 'alias nix-open=". /root/.nix-profile/etc/profile.d/nix.sh"' >> /root/.profile

# pin Nixpkgs to a specific commit (2023.11.17)
RUN . /root/.nix-profile/etc/profile.d/nix.sh && \
    mkdir -p /root/nix && \
    echo 'import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/46688f8eb5.tar.gz") {}' > /root/nix/pinned-nixpkgs.nix

# install jq + sqlite using the pinned Nixpkgs
RUN . /root/.nix-profile/etc/profile.d/nix.sh && \
    nix-env -f /root/nix/pinned-nixpkgs.nix -iA jq sqlite

COPY clean_db.sql /tmp/clean_db.sql

RUN echo "path" > /tmp/required_paths.txt
RUN . /root/.nix-profile/etc/profile.d/nix.sh && \
    PAGER='' nix-store -q --requisites $(which jq) >> /tmp/required_paths.txt
RUN sqlite3 /nix/var/nix/db/db.sqlite "CREATE TEMP TABLE IF NOT EXISTS RequiredPaths (path TEXT PRIMARY KEY);"
RUN sqlite3 /nix/var/nix/db/db.sqlite ".mode list" ".import /tmp/required_paths.txt RequiredPaths"
RUN sqlite3 /nix/var/nix/db/db.sqlite < /tmp/clean_db.sql

FROM scratch

COPY --from=builder /nix/var/nix/db/db.sqlite /nix/var/nix/db/db.sqlite
