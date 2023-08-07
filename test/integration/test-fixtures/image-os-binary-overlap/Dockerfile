FROM alpine:latest

# syft should not longer show the binary package for this image:
# https://github.com/anchore/syft/issues/931
# busybox                 1.36.1       binary <-- not reported synthetic package overlap
# busybox                 1.36.1-r0    apk
RUN apk update && apk add busybox
