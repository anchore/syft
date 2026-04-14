# This represents a basic .NET project build where the project dependencies are downloaded and the project is built.
# The output is a directory tree of DLLs, a project.lock.json (not used in these tests), a .deps.json file, and
# a .runtimeconfig.json file (not used in these tests).
# With this deployment strategy there IS a bundled runtime.
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

FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/runtime:8.0@sha256:a6fc92280fbf2149cd6846d39c5bf7b9b535184e470aa68ef2847b9a02f6b99e
WORKDIR /app
COPY --from=build /app .
# just a nice to have for later...
#COPY --from=build /src/packages.lock.json .

# this is a more realistic application image since the runtime is with the app
ENTRYPOINT ["dotnet", "dotnetapp.dll"]

