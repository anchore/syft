# Stage 1: For CA certs
FROM gcr.io/distroless/static-debian12:latest AS build

# Stage 2: Final stage with secure non-root user
FROM gcr.io/distroless/base-debian12

# Set up certificates
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# ====== Define a safe non-root user manually (1000:1000) ======
# UID 1000 is typically a safe, non-root value
# Create minimal passwd/group files manually — no shell binaries needed
RUN echo "nonroot:x:1000:1000:Syft NonRoot:/home/nonroot:/sbin/nologin" > /etc/passwd && \
    echo "nonroot:x:1000:" > /etc/group && \
    mkdir -p /home/nonroot && \
    chown 1000:1000 /home/nonroot

# ====== Add binary ======
COPY syft /
WORKDIR /home/nonroot

# Drop privileges
USER 1000:1000

# Build metadata
ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.title="syft"
LABEL org.opencontainers.image.description="CLI tool and library for generating a Software Bill of Materials from container images and filesystems"
LABEL org.opencontainers.image.source=$VCS_URL
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.version=$BUILD_VERSION
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.artifacthub.package.readme-url="https://raw.githubusercontent.com/anchore/syft/main/README.md"
LABEL io.artifacthub.package.logo-url="https://user-images.githubusercontent.com/5199289/136844524-1527b09f-c5cb-4aa9-be54-5aa92a6086c1.png"
LABEL io.artifacthub.package.license="Apache-2.0"

ENTRYPOINT ["/syft"]
