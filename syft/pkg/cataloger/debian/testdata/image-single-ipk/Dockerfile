# assembles a Yocto-style .ipk the same way bitbake's package_ipk does (opkg-build: a GNU ar archive of
# debian-binary, control.tar.gz and data.tar.zst) without paying for a full Yocto build. control/ is copied
# verbatim from libz1_1.3.2-r0_x86-64-v3.ipk built by poky-tiny (wrynose); the library itself is a stub
# since only the archive shape and control metadata matter here.
FROM alpine:3.18.4@sha256:48d9183eb12a05c99bcc0bf44a003607b8e941e1d4f41f9ad12bdcc4b5672f86 AS build

RUN apk add --no-cache binutils zstd

COPY control /pkg/control

RUN mkdir -p /pkg/data/usr/lib \
    && echo stub > /pkg/data/usr/lib/libz.so.1.3.2 \
    && ln -s libz.so.1.3.2 /pkg/data/usr/lib/libz.so.1 \
    && cd /pkg \
    && echo 2.0 > debian-binary \
    && tar -C control -czf control.tar.gz . \
    && tar -C data -cf - . | zstd -q -o data.tar.zst \
    && ar rcD /libz1_1.3.2-r0_x86-64-v3.ipk debian-binary control.tar.gz data.tar.zst

FROM scratch
COPY --from=build /libz1_1.3.2-r0_x86-64-v3.ipk /
