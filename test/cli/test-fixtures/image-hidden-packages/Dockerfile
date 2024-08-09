FROM alpine:3.20.1@sha256:dabf91b69c191a1a0a1628fd6bdd029c0c4018041c7f052870bb13c5a222ae76
# all-layers scope should pickup on vsftpd
RUN apk update && apk add -f vsftpd
RUN apk del -f vsftpd
