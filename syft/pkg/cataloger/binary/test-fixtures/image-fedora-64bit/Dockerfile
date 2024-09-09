FROM --platform=linux/amd64 fedora:41@sha256:c05bf79137835bf5c521c58f8252d6031780ae865a0379ab57f412e0ac6b42aa AS build


FROM scratch
COPY --from=build /bin/sha256sum /sha256sum
COPY --from=build /bin/sha1sum /sha1sum
