FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:3f93439f47fea888d94e6e228d0d0de841f4122ef46f8bfd04f8bd78cbce7ddb AS build
ARG RUNTIME=win-x64
WORKDIR /src

COPY src/helloworld.csproj .
RUN dotnet restore -r $RUNTIME

COPY src/*.cs .

RUN dotnet publish -c Release --no-restore -o /app

# note: we're not using a runtime here to make testing easier... but this functionally will not work if this was a produciton app
FROM busybox:latest

WORKDIR /app

COPY --from=build /app .
