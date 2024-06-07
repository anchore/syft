FROM --platform=linux/amd64 fedora:41 as build

FROM scratch
COPY --from=build /bin/sha256sum /sha256sum
COPY --from=build /bin/sha1sum /sha1sum
