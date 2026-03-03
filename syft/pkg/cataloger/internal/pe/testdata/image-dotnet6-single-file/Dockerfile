FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY src/ .
RUN dotnet publish -c Release -r win-x64 \
    -p:PublishSingleFile=true \
    -p:SelfContained=true \
    -o /app

FROM busybox
WORKDIR /app
COPY --from=build /app/hello.exe .
