# Runs an AutoHttps application on Linux, consuming the package exactly as a customer would.
# Everything here exercises code paths that never run on a Windows developer machine.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY packages/ /packages/
COPY App/ ./
RUN dotnet nuget add source /packages -n local \
 && dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
RUN mkdir -p /certs
COPY --from=build /app /app
COPY trust/*.pem /usr/local/share/ca-certificates/
RUN for f in /usr/local/share/ca-certificates/*.pem; do mv "$f" "${f%.pem}.crt"; done \
 && update-ca-certificates
WORKDIR /app
ENTRYPOINT ["dotnet", "App.dll"]
