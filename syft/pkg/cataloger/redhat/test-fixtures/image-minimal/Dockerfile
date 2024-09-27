# linux/amd64
FROM rockylinux:9.3.20231119@sha256:45cc42828cc5ceeffa3a9b4f6363fb582fac3ab91f77bf403daa067f8f049f96

ADD remove.sh /remove.sh
RUN /remove.sh

# let's only keep what we need for testing (not the intermediate layers)
FROM scratch
COPY --from=0 / /
