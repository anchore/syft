FROM alpine:3.17.1@sha256:93d5a28ff72d288d69b5997b8ba47396d2cbb62a72b5d87cd3351094b5d578a0 as tools
FROM scratch
COPY --from=tools /bin /bin
COPY --from=tools /lib /lib
ADD . .
RUN rm -rf file-1.txt /bin /lib
