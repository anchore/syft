FROM busybox:latest AS base

RUN wget https://s3.amazonaws.com/jruby.org/downloads/9.3.15.0/jruby_windows_9_3_15_0.exe -O jruby.exe

FROM scratch
COPY --from=base /jruby.exe /jruby.exe
