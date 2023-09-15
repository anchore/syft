FROM debian:sid@sha256:bee393b48f83fdeb978ce68abb9dc955d6398b984fca88b52a09dceb45ac74b5
ADD sources.list /etc/apt/sources.list.d/sources.list
RUN apt update -y && apt install -y dpkg-dev
# this as a "macho-invalid" directory which is useful for testing
RUN apt-get source -y clang-13
