FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/core/sdk:2.2 AS build
ARG RUNTIME=win-x64
WORKDIR /src

COPY src/helloworld.csproj .
RUN dotnet restore -r $RUNTIME

COPY src/*.cs .

RUN dotnet publish -c Release --no-restore -o /app

FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/core/runtime:2.2
WORKDIR /app
COPY --from=build /app .

# this is a realistic application image since the runtime is with the app
ENTRYPOINT ["dotnet", "HelloWorld.dll"]
