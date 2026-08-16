# This is the same as the net8-app image, however, the entire .NET runtime is compiled into a single binary, residing with the application.
FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:7d3a75ca5c8ac4679908ef7a2591b9bc257c62bd530167de32bba105148bb7be AS build
ARG RUNTIME=linux-musl-x64
WORKDIR /src

COPY src/*.csproj .
COPY src/packages.lock.json .
RUN dotnet restore -r $RUNTIME --verbosity normal --locked-mode --force-evaluate

COPY src/ .
RUN dotnet publish -r $RUNTIME -p:PublishSingleFile=true -p:RestorePackagesWithLockFile=true -p:ErrorOnDuplicatePublishOutputFiles=false --self-contained true -p:EnableCompressionInSingleFile=true -p:DebugSymbols=false -p:DebugType=None  -o /app


FROM busybox
WORKDIR /app
COPY --from=build /app .