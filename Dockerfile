FROM alpine:latest AS build

# add required ca-certificates for https request.
RUN apk --no-cache add ca-certificates

# create empty directory for scratch image cache.
RUN mkdir -p /tmp-syft

# reduce container image to scratch size.
FROM scratch

# Copy directories and files needed to execute syft.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /tmp-syft /tmp

# copy syft binary to rootfs
COPY syft /

# default path
ENTRYPOINT ["/syft"]
