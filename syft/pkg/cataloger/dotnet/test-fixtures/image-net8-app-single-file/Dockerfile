FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
ARG TARGETARCH=x64
WORKDIR /src

# copy csproj and restore as distinct layers
COPY src/*.csproj .
RUN dotnet restore --arch $TARGETARCH --verbosity normal

# copy and publish app and libraries (single file)
COPY src/ .
RUN dotnet publish --arch $TARGETARCH -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishReadyToRun=true -p:PublishSingleFile=true -p:PublishTrimmed=true --no-restore -o /app


FROM busybox
WORKDIR /app
COPY --from=build /app .
