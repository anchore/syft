FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
ARG RUNTIME=win-x64

COPY . .
WORKDIR /src
RUN dotnet restore -r $RUNTIME
RUN dotnet publish -c Release --no-restore -o /app

FROM busybox:latest
WORKDIR /app
COPY --from=build /app .


