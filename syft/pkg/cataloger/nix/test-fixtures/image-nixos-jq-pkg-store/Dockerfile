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

# install jq using the pinned Nixpkgs
RUN . /root/.nix-profile/etc/profile.d/nix.sh && \
    nix-env -f /root/nix/pinned-nixpkgs.nix -iA jq

# create a directory with only the required dependencies + any derivations
RUN . /root/.nix-profile/etc/profile.d/nix.sh && \
    mkdir -p /nix-minimal && \
    for dep in $(nix-store -q --requisites $(which jq)); do \
        mkdir -p /nix-minimal$(dirname $dep) && \
        cp -a $dep /nix-minimal$dep; \
    done

# now add all the drv files from the store
RUN . /root/.nix-profile/etc/profile.d/nix.sh && \
    for drv in $(find /nix/store -name "*.drv"); do \
        mkdir -p /nix-minimal$(dirname $drv) && \
        cp -a $drv /nix-minimal$drv; \
    done

FROM scratch

COPY --from=builder /nix-minimal/nix/store /nix/store
