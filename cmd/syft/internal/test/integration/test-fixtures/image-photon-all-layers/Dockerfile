FROM photon:5.0-20230729@sha256:4cf2a1ce0a3f4625f13a0becb6b9bccfdb014c565be6e9a2ec4c4aad1ff8a5d9 AS base

FROM scratch

COPY --from=base /usr/lib/sysimage/rpm /usr/lib/sysimage/rpm
