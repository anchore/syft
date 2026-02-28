FROM gcr.io/distroless/static-debian12:latest AS build

FROM scratch
# needed for version check HTTPS request
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# create the /tmp dir, which is needed for image content cache
WORKDIR /tmp

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/syft /

ENTRYPOINT ["/syft"]
