FROM alpine:latest AS build

RUN apk --no-cache add ca-certificates

FROM scratch
# needed for version check HTTPS request
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# create the /tmp dir, which is needed for image content cache
WORKDIR /tmp

COPY syft /

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="syft"
LABEL org.label-schema.description="CLI tool and library for generating a Software Bill of Materials from container images and filesystems"
LABEL org.label-schema.vcs-url=$VCS_URL
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vendor="Anchore, Inc."
LABEL org.label-schema.version=$BUILD_VERSION

ENTRYPOINT ["/syft"]
