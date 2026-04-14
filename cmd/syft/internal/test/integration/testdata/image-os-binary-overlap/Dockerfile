FROM alpine:3.18.3@sha256:7144f7bab3d4c2648d7e59409f15ec52a18006a128c733fcff20d3a4a54ba44a

# syft should not longer show the binary package for this image:
# https://github.com/anchore/syft/issues/931
# busybox                 1.36.1       binary <-- not reported synthetic package overlap
# busybox                 1.36.1-r0    apk
RUN apk update && apk add busybox
