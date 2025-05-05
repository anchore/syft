FROM --platform=linux/amd64 nixos/nix:2.28.2@sha256:4215204b5f65c7b756b26a6dd47a6af77f1d906e5edf62b184c95420a7dfa08f AS builder

# cross-platform builds cannot use bpf features
RUN mkdir -p /etc/nix && \
    echo 'filter-syscalls = false' > /etc/nix/nix.conf && \
    echo 'experimental-features = nix-command flakes' >> /etc/nix/nix.conf

# pin Nixpkgs to a specific commit (2023.11.17)
RUN mkdir -p /root/nix && \
    echo 'import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/46688f8eb5.tar.gz") {}' > /root/nix/pinned-nixpkgs.nix

# install jq using the pinned Nixpkgs
RUN nix-env -f /root/nix/pinned-nixpkgs.nix -iA jq

# create a directory with only the required dependencies + any derivations
RUN mkdir -p /nix-minimal && \
    for dep in $(nix-store -q --requisites $(which jq)); do \
        mkdir -p /nix-minimal$(dirname $dep) && \
        cp -a $dep /nix-minimal$dep; \
    done

# now add all the drv files from the store
RUN for drv in $(find /nix/store -name "*.drv"); do \
        mkdir -p /nix-minimal$(dirname $drv) && \
        cp -a $drv /nix-minimal$drv; \
    done

FROM scratch

COPY --from=builder /nix-minimal/nix/store /nix/store
