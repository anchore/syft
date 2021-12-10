FROM debian:sid
ADD sources.list /etc/apt/sources.list.d/sources.list
RUN apt update -y && apt install -y dpkg-dev
# this as a "macho-invalid" directory which is useful for testing
RUN apt-get source -y clang-13
