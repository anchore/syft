FROM --platform=linux/amd64 cgr.dev/chainguard/wolfi-base AS build

FROM scratch
COPY --from=build /lib/libBrokenLocale.so.1 /lib/libBrokenLocale.so.1

CMD ["/bin/sh"]

