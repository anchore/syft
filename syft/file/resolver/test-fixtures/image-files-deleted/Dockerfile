FROM alpine:3.17.1 as tools
FROM scratch
COPY --from=tools /bin /bin
COPY --from=tools /lib /lib
ADD . .
RUN rm -rf file-1.txt /bin /lib
