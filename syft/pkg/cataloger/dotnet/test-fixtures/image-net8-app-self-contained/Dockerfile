# This is the same as the net8-app image, however, the .NET runtime is copied to the target directory tree. There
# is no bundling to include the runtime within a single archive/binary.
FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:7d3a75ca5c8ac4679908ef7a2591b9bc257c62bd530167de32bba105148bb7be AS build
ARG RUNTIME=win-x64
WORKDIR /src

# copy csproj and restore as distinct layers
COPY src/*.csproj .
COPY src/packages.lock.json .
RUN dotnet restore -r $RUNTIME --verbosity normal --locked-mode

# copy and publish app and libraries (self-contained!)
COPY src/ .
RUN dotnet publish -r $RUNTIME --self-contained --no-restore -o /app


FROM busybox
WORKDIR /app
COPY --from=build /app .
# just a nice to have for later...
#COPY --from=build /src/packages.lock.json .