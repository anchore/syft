# This represents a basic .NET project build where the project dependencies are downloaded and the project is built.
# The output is a directory tree of DLLs, a project.lock.json (not used in these tests), a .deps.json file, and
# a .runtimeconfig.json file (not used in these tests). With this deployment strategy there is no bundled runtime.
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

# $ dotnet list package --include-transitive
# Project 'dotnetapp' has the following package references
#   [net8.0]:
#   Top-level Package      Requested   Resolved
#   > Humanizer            2.14.1      2.14.1
#   > Newtonsoft.Json      13.0.3      13.0.3
#
#   Transitive Package               Resolved
#   > Humanizer.Core                 2.14.1
#   > Humanizer.Core.af              2.14.1
#   > Humanizer.Core.ar              2.14.1
#   > Humanizer.Core.az              2.14.1
#   > Humanizer.Core.bg              2.14.1
#   > Humanizer.Core.bn-BD           2.14.1
#   > Humanizer.Core.cs              2.14.1
#   > Humanizer.Core.da              2.14.1
#   > Humanizer.Core.de              2.14.1
#   > Humanizer.Core.el              2.14.1
#   > Humanizer.Core.es              2.14.1
#   > Humanizer.Core.fa              2.14.1
#   > Humanizer.Core.fi-FI           2.14.1
#   > Humanizer.Core.fr              2.14.1
#   > Humanizer.Core.fr-BE           2.14.1
#   > Humanizer.Core.he              2.14.1
#   > Humanizer.Core.hr              2.14.1
#   > Humanizer.Core.hu              2.14.1
#   > Humanizer.Core.hy              2.14.1
#   > Humanizer.Core.id              2.14.1
#   > Humanizer.Core.is              2.14.1
#   > Humanizer.Core.it              2.14.1
#   > Humanizer.Core.ja              2.14.1
#   > Humanizer.Core.ko-KR           2.14.1
#   > Humanizer.Core.ku              2.14.1
#   > Humanizer.Core.lv              2.14.1
#   > Humanizer.Core.ms-MY           2.14.1
#   > Humanizer.Core.mt              2.14.1
#   > Humanizer.Core.nb              2.14.1
#   > Humanizer.Core.nb-NO           2.14.1
#   > Humanizer.Core.nl              2.14.1
#   > Humanizer.Core.pl              2.14.1
#   > Humanizer.Core.pt              2.14.1
#   > Humanizer.Core.ro              2.14.1
#   > Humanizer.Core.ru              2.14.1
#   > Humanizer.Core.sk              2.14.1
#   > Humanizer.Core.sl              2.14.1
#   > Humanizer.Core.sr              2.14.1
#   > Humanizer.Core.sr-Latn         2.14.1
#   > Humanizer.Core.sv              2.14.1
#   > Humanizer.Core.th-TH           2.14.1
#   > Humanizer.Core.tr              2.14.1
#   > Humanizer.Core.uk              2.14.1
#   > Humanizer.Core.uz-Cyrl-UZ      2.14.1
#   > Humanizer.Core.uz-Latn-UZ      2.14.1
#   > Humanizer.Core.vi              2.14.1
#   > Humanizer.Core.zh-CN           2.14.1
#   > Humanizer.Core.zh-Hans         2.14.1
#   > Humanizer.Core.zh-Hant         2.14.1

# lets pull in a file that is not related at all and in fact is not a .NET binary either (this should be ignored)
RUN wget -O /app/jruby_windows_9_3_15_0.exe https://s3.amazonaws.com/jruby.org/downloads/9.3.15.0/jruby_windows_9_3_15_0.exe

FROM busybox
WORKDIR /app
COPY --from=build /app .
# just a nice to have for later...
#COPY --from=build /src/packages.lock.json .
