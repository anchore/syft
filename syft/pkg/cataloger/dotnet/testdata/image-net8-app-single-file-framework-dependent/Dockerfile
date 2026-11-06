# This is the same as the net8-app-single-file image, however, the app is published framework-dependent (without the runtime).
# This means the apphost is a native PE (no CLR header) with the application and its dependencies (including the deps.json)
# bundled after the PE image.
FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:7d3a75ca5c8ac4679908ef7a2591b9bc257c62bd530167de32bba105148bb7be AS build
ARG RUNTIME=win-x64
WORKDIR /src

# copy csproj and restore as distinct layers
COPY src/*.csproj .
COPY src/packages.lock.json .
RUN dotnet restore -r $RUNTIME --verbosity normal --locked-mode

# copy and publish app and libraries (single file, framework-dependent)
COPY src/ .
RUN dotnet publish -r $RUNTIME --self-contained false -p:PublishSingleFile=true --no-restore -o /app


FROM busybox
WORKDIR /app
COPY --from=build /app .
