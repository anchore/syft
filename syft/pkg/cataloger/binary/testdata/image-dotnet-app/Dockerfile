FROM alpine:latest AS builder

RUN apk add --no-cache wget unzip
RUN mkdir -p /app
RUN wget -O /app/minver.nupkg https://www.nuget.org/api/v2/package/minver-cli/4.3.0
RUN unzip /app/minver.nupkg -d /app/minver

from busybox:latest

COPY --from=builder /app/minver /minver
