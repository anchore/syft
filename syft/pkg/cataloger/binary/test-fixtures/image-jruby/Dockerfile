FROM --platform=linux/amd64 alpine:latest AS builder

RUN wget -O jruby_windows_9_3_15_0.exe https://s3.amazonaws.com/jruby.org/downloads/9.3.15.0/jruby_windows_9_3_15_0.exe

FROM scratch

COPY --from=builder /jruby_windows_9_3_15_0.exe /jruby_windows_9_3_15_0.exe