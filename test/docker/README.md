# Linux container test rig

Runs an AutoHttps application on Linux, consuming the NuGet package the way a customer would. It
exercises the paths that never run on a Windows developer machine: chain building without CryptoAPI
filling in intermediates, file modes, and a container that is restarted with a mounted volume.

The package is built locally rather than committed, so produce it first:

```
dotnet pack src/AutoHttps/AutoHttps.csproj -c Release -o test/docker/packages
docker build -t autohttps-linux-app test/docker
```

The image trusts `trust/pebble.minica.pem` so the application can reach a Pebble server started by
`test/pebble/docker-compose.yml` over the `autohttps-acme` network:

```
docker run --rm --network autohttps-acme \
  -e DOMAIN=app.autohttps.test \
  -e ACME_DIRECTORY=https://pebble:14000/dir \
  autohttps-linux-app
```

`MODE=listener` (the default) wires the endpoint with `UseAutoHttps` so the full chain is sent;
`MODE=defaults` uses Kestrel's HTTPS defaults instead. `PROFILE`, `RENEWAL_THRESHOLD` and
`RENEWAL_CHECK_SECONDS` compress months of renewals into minutes for soak testing.

## HTTP/3

`PROTOCOLS=h3` puts `Http1AndHttp2AndHttp3` on the HTTPS endpoint, and `SELFTEST=h3` makes the
application issue a real HTTP/3 request against its own endpoint once a certificate has arrived. This
is the only place HTTP/3 can be exercised here: Windows 10 has no MsQuic, so `QuicListener.IsSupported`
is false on the development machine and the integration suite skips the QUIC half.

The self-test reaches the certificate's own name through a hosts entry, and validates the chain
against the authority's issuing root rather than the system trust store, so a pass means QUIC
negotiated, the managed certificate was chosen from the SNI, and the chain verified:

```
docker run --rm --network autohttps-acme \
  --add-host app.autohttps.test:127.0.0.1 \
  -e DOMAIN=app.autohttps.test \
  -e ACME_DIRECTORY=https://pebble:14000/dir \
  -e PROTOCOLS=h3 -e SELFTEST=h3 \
  -e TRUST_ROOTS_URL=https://pebble:15000/roots/0 \
  -e TRUST_INTERMEDIATES_URL=https://pebble:15000/intermediates/0 \
  autohttps-linux-app
```

Pebble resolves the domain through challtestsrv, so point it at the container before validation runs:
`curl -X POST -d '{"ip":"<container ip>"}' http://localhost:8055/set-default-ipv4`.

The `chain=` value in the result is the point of supplying the intermediate separately. `MODE=listener`
reports `chain=2`, the leaf and its intermediate, because that wiring hands Kestrel a certificate
context. `MODE=defaults` reports `chain=1`: Kestrel drops a configured chain whenever a certificate
selector is in use, over QUIC exactly as over TCP, so that endpoint presents the leaf alone and the
client has to complete the chain itself.

**Note:** `dotnet pack` writes the package into `packages/`, which `.gitignore` excludes. A fresh
clone has an empty `packages/` directory and the image will not build until the pack step is run.
