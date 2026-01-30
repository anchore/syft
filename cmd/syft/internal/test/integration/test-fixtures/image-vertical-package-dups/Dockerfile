FROM --platform=linux/amd64 rockylinux:9.3.20231119@sha256:d644d203142cd5b54ad2a83a203e1dee68af2229f8fe32f52a30c6e1d3c3a9e0 AS base

# modifying the RPM DB multiple times will result in duplicate packages when using all-layers (if there was no de-dup logic)
# curl is tricky, it already exists in the image and is being upgraded

# but... we want to make the test image as small as possible, so we are making the changes in stages and then
# copying the RPM DB from each stage to a final stage in separate layers. This will result in a much smaller image.

FROM base AS stage1
RUN dnf install -y wget

FROM stage1 AS stage2
RUN dnf update -y curl-minimal

FROM stage2 AS stage3
RUN dnf install -y vsftpd

FROM stage3 AS stage4
RUN dnf install -y httpd

FROM scratch

COPY --from=base /var/lib/rpm /var/lib/rpm
COPY --from=stage1 /var/lib/rpm /var/lib/rpm
COPY --from=stage2 /var/lib/rpm /var/lib/rpm
COPY --from=stage3 /var/lib/rpm /var/lib/rpm
COPY --from=stage4 /var/lib/rpm /var/lib/rpm
