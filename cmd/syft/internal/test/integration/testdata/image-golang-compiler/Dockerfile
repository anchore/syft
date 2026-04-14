FROM --platform=linux/amd64 golang:1.18.10-alpine

FROM scratch

# we don't need the entire golang toolchain, just a single binary with the stdlib baked in
COPY --from=0 /usr/local/go/bin/gofmt bin/gofmt
