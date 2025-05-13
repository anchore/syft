FROM fedora:35@sha256:36af84ba69e21c9ef86a0424a090674c433b2b80c2462e57503886f1d823abe8 AS base

# lets save some space
FROM scratch

COPY --from=base /var/lib/rpm /var/lib/rpm
