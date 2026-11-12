# note: this is published framework-dependent on purpose: the bundle format (what these fixtures exercise) is
# identical either way, but bundling the runtime makes the fixture ~60MB instead of ~160KB, which dominates
# the runtime of the tests that load this image.
FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY src .
RUN dotnet publish -c Release -r win-x64 \
    -p:PublishSingleFile=true \
    -p:SelfContained=false \
    -o /app

FROM busybox
WORKDIR /app
COPY --from=build /app/hello.exe .
