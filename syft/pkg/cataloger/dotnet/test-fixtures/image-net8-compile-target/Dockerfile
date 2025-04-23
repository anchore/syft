FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:3f93439f47fea888d94e6e228d0d0de841f4122ef46f8bfd04f8bd78cbce7ddb AS build
ARG RUNTIME=win-x64
WORKDIR /src

COPY src/helloworld.csproj .
RUN dotnet restore -r $RUNTIME

COPY src/*.cs .
RUN dotnet publish -c Release -r $RUNTIME --self-contained false -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS runtime
WORKDIR /app
COPY --from=build /app .

ENTRYPOINT ["dotnet", "HelloWorld.dll"]
