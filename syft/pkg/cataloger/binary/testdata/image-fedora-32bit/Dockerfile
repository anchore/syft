FROM --platform=linux/arm arm32v7/fedora:36 AS build

FROM scratch
COPY --from=build /bin/sha256sum /sha256sum
COPY --from=build /bin/sha1sum /sha1sum
