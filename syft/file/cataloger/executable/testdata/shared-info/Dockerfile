# syntax=docker/dockerfile:1

ARG OSXCROSS_VERSION=13.1
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM crazymax/osxcross:${OSXCROSS_VERSION}-ubuntu AS osxcross

FROM --platform=$BUILDPLATFORM ubuntu:22.04

RUN apt update -y && apt install -y \
    curl wget \
    make gcc clang \
    git mingw-w64

COPY --from=osxcross /osxcross /osxcross
ENV PATH="/osxcross/bin:$PATH"
ENV LD_LIBRARY_PATH="/osxcross/lib:$LD_LIBRARY_PATH"
