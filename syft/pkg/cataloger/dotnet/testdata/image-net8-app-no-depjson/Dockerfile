# This is the same as the net8-app image, but without the .deps.json file.
FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:7d3a75ca5c8ac4679908ef7a2591b9bc257c62bd530167de32bba105148bb7be AS build
ARG RUNTIME=win-x64
WORKDIR /src

# copy csproj and restore as distinct layers
COPY src/*.csproj .
COPY src/packages.lock.json .
RUN dotnet restore -r $RUNTIME --verbosity normal --locked-mode

# copy and publish app and libraries
COPY src/ .
RUN dotnet publish -r $RUNTIME --no-restore -o /app

# important!
RUN rm /app/*.deps.json

FROM busybox
WORKDIR /app
COPY --from=build /app .
# just a nice to have for later...
#COPY --from=build /src/packages.lock.json .