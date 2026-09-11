FROM ubuntu:22.04 AS downloader

RUN apt-get update && apt-get install -y curl

# launchpad's +files URLs are immutable, unlike pool/main which only keeps the current version
RUN curl -fsSL -o zlib1g.deb https://launchpad.net/ubuntu/+archive/primary/+files/zlib1g_1.3.dfsg-3.1ubuntu2.1_amd64.deb

FROM scratch

COPY --from=downloader /zlib1g.deb /zlib1g.deb
