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

**Note:** `dotnet pack` writes the package into `packages/`, which `.gitignore` excludes. A fresh
clone has an empty `packages/` directory and the image will not build until the pack step is run.
