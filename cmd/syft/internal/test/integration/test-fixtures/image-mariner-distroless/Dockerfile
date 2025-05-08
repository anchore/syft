FROM mcr.microsoft.com/cbl-mariner/distroless/base:2.0.202205275@sha256:f550c5428df17b145851ad75983aca6d613ad4b51ca7983b2a83e67d0ac91a5d AS base

# let's shoot for smaller test fixtures
FROM scratch

COPY --from=base /var/lib/rpmmanifest/container-manifest-2 /var/lib/rpmmanifest/container-manifest-2
COPY --from=base /usr/bin/gencat /usr/bin/gencat
COPY --from=base /usr/bin/openssl /usr/bin/openssl
