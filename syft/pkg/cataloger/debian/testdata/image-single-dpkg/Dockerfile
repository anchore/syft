FROM ubuntu:22.04 AS downloader

RUN apt-get update && apt-get install -y curl

RUN curl -o zlib1g.deb http://archive.ubuntu.com/ubuntu/pool/main/z/zlib/zlib1g_1.3.dfsg-3.1ubuntu2.1_amd64.deb

FROM scratch

COPY --from=downloader /zlib1g.deb /zlib1g.deb
