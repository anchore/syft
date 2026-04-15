FROM --platform=linux/amd64 cgr.dev/chainguard/wolfi-base@sha256:9a74366aa10eff2bf14dab0948123bd2c51703e1c553a73740ef687f723aecf4 AS build

FROM scratch
COPY --from=build /lib/libBrokenLocale.so.1 /lib/libBrokenLocale.so.1

CMD ["/bin/sh"]

