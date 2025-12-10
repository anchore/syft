FROM alpine:3.21

RUN apk add --no-cache clang18 musl-dev make

# create symlink so 'clang' command works (Alpine installs as clang-18)
RUN ln -s /usr/bin/clang-18 /usr/bin/clang
