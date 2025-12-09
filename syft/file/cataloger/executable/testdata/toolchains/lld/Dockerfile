FROM alpine:3.21.7@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

RUN apk add --no-cache clang18 lld musl-dev make

# create symlink so 'clang' command works (Alpine installs as clang-18)
RUN ln -s /usr/bin/clang-18 /usr/bin/clang
