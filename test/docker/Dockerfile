# Runs an AutoHttps application on Linux, consuming the package exactly as a customer would.
# Everything here exercises code paths that never run on a Windows developer machine.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY packages/ /packages/
COPY App/ ./
RUN dotnet restore --source /packages \
 && dotnet publish -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
RUN mkdir -p /certs
# libmsquic is what Kestrel needs to serve HTTP/3 on Linux. It does not ship with .NET and it is not
# in the distribution's own archive, only in Microsoft's, which is the part that catches people out:
# without it an endpoint that asks for HTTP/3 simply binds nothing on UDP.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && . /etc/os-release \
 && curl -fsSL "https://packages.microsoft.com/config/${ID}/${VERSION_ID}/packages-microsoft-prod.deb" \
      -o /tmp/packages-microsoft-prod.deb \
 && dpkg -i /tmp/packages-microsoft-prod.deb \
 && apt-get update \
 && apt-get install -y --no-install-recommends libmsquic \
 && rm -f /tmp/packages-microsoft-prod.deb \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /app /app
COPY trust/*.pem /usr/local/share/ca-certificates/
RUN for f in /usr/local/share/ca-certificates/*.pem; do mv "$f" "${f%.pem}.crt"; done \
 && update-ca-certificates
WORKDIR /app
ENTRYPOINT ["dotnet", "App.dll"]
