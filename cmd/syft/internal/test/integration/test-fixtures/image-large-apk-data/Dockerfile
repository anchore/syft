FROM alpine@sha256:d9a7354e3845ea8466bb00b22224d9116b183e594527fb5b6c3d30bc01a20378

# we keep these unpinned so that if alpine
# changes our integration tests can adapt
RUN apk add --no-cache \
            tzdata \
            vim \
            alpine-sdk
