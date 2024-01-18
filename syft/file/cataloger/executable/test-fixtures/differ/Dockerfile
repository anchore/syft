#FROM alpine:3.19
#RUN apk add difftastic
#ENTRYPOINT ["difft"]
FROM fedora:40
RUN dnf install -y git-delta git
ENTRYPOINT ["delta"]