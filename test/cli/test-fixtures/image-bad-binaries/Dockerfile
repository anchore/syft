FROM debian:sid@sha256:27c460e2384b59651035abba14f4ad0885205747674148d0b7de3847042bdcf5
ADD sources.list /etc/apt/sources.list.d/sources.list
RUN apt update -y && apt install -y dpkg-dev
# this as a "macho-invalid" directory which is useful for testing
RUN apt-get source -y clang-13
