FROM alpine:latest

# without the overlap package filter syft should report:
# busybox                 1.36.1       binary
  #busybox                 1.36.1-r0    apk
RUN apk update && apk add busybox