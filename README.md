# AutoHttps

[![NuGet](https://img.shields.io/nuget/v/AutoHttps?logo=nuget&label=NuGet&color=004880)](https://www.nuget.org/packages/AutoHttps)
[![Downloads](https://img.shields.io/nuget/dt/AutoHttps?logo=nuget&label=downloads&color=004880)](https://www.nuget.org/packages/AutoHttps)
[![CI](https://github.com/astralmaster/AutoHttps/actions/workflows/ci.yml/badge.svg)](https://github.com/astralmaster/AutoHttps/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://github.com/astralmaster/AutoHttps/blob/main/LICENSE)

**Automatic HTTPS for ASP.NET Core.** Add one package; your app obtains and renews its own TLS
certificate from Let's Encrypt (or any ACME certificate authority) with no external dependencies.

```csharp
builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add("example.com");
    options.EmailAddress = "admin@example.com";
    options.AcceptTermsOfService = true;
});
```

That is the whole setup. AutoHttps wires up Kestrel, answers the `http-01` challenge from your own
request pipeline, writes the certificate to disk so it survives a restart, and renews on the
schedule the certificate authority asks for.

---

## Why this exists

[`LettuceEncrypt`](https://github.com/natemcmaster/LettuceEncrypt), the library everyone used, was
archived in April 2025. Its last release targets .NET 6, which went out of support in November 2024.
Microsoft's own YARP documentation still describes it, above a note saying it "is archived and no
longer supported, so the package isn't recommended for use", and names no replacement.

Meanwhile the certificate world moved:

- Let's Encrypt now issues **six-day certificates** and is taking the default lifetime from 90 days
  down to 45. A client that renews on a fixed 30-day threshold cannot cope with either.
- **ACME Renewal Information** became [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html) in
  September 2025. Authorities now tell clients *when* to renew, and expect to be asked.
- **Certificate profiles** are how you opt into the shorter lifetimes.

AutoHttps implements all three. Moving an app off LettuceEncrypt? See
[Migrating from LettuceEncrypt](MIGRATION.md).

## Installation

```
dotnet add package AutoHttps
```

Targets `net8.0` and `net10.0`. **Zero NuGet dependencies.** Everything it needs is in the ASP.NET
Core shared framework, including a complete RFC 8555 client written for this library.

## Requirements

- **Kestrel must terminate TLS.** A reverse proxy in front is fine and common. See
  [Running behind a proxy](#running-behind-a-proxy). What does not work is another component
  terminating TLS for you: IIS, Azure App Service, or an nginx that holds its own certificate. In
  that case the certificate belongs on that component, not here.
- The domain must resolve to **whatever answers HTTP for it at your edge**, and the certificate
  authority must be able to reach that edge on **port 80** for `http-01`. The port your application
  listens on internally does not matter; a proxy may forward from 80 to anything. If port 80 is not
  reachable at all, use `dns-01` instead (below).
- Give the storage directory a durable home. See [Storage](#storage).

## What you get

| | |
|---|---|
| **Challenges** | `http-01` and `dns-01` |
| **Wildcards** | Yes, via `dns-01` |
| **Renewal** | ACME Renewal Information (RFC 9773), with a lifetime-proportional fallback |
| **Profiles** | `classic`, `tlsserver`, `shortlived`. Six-day certificates work out of the box |
| **Authorities** | Let's Encrypt, ZeroSSL, Google Trust Services, Buypass, or any ACME directory |
| **External account binding** | Yes, required by ZeroSSL and Google Trust Services |
| **Keys** | ECDSA P-256 (default), P-384, RSA 2048/3072/4096 |
| **Multiple instances** | Locked and shared through the certificate store |
| **Dependencies** | None |

## Configuration

Everything below is optional except the three settings in the quick start.

```csharp
builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add("example.com");
    options.DomainNames.Add("www.example.com");
    options.EmailAddress = "admin@example.com";
    options.AcceptTermsOfService = true;

    // Develop against staging. Production rate limits are easy to exhaust while debugging a setup.
    options.CertificateAuthority = CertificateAuthorities.LetsEncryptStaging;

    // Six-day certificates, if the authority offers that profile. AutoHttps then renews them
    // several times a week without further configuration. Profile names vary between authorities;
    // the CertificateProfiles constants are the ones Let's Encrypt publishes.
    options.Profile = CertificateProfiles.ShortLived;

    options.KeyAlgorithm = KeyAlgorithm.EcdsaP256;
    options.StorageDirectory = "/var/lib/myapp/certs";
});
```

Or bind from configuration:

```csharp
builder.Services.AddAutoHttps(builder.Configuration.GetSection("AutoHttps"));
```

```json
{
  "AutoHttps": {
    "DomainNames": [ "example.com", "www.example.com" ],
    "EmailAddress": "admin@example.com",
    "AcceptTermsOfService": true,
    "StorageDirectory": "/var/lib/myapp/certs"
  }
}
```

A misconfigured application **fails while the host is being built**, listing every problem at once,
before it binds a port.

### Every option

The quick start covers the common case. These are the rest:

| Option | Default | What it does |
|---|---|---|
| `DomainNames` | *(required)* | Domains to request. A `*.` entry needs `DnsChallengeProvider`. |
| `EmailAddress` | *(required)* | Contact registered with the authority. |
| `AcceptTermsOfService` | `false` | Must be `true`. Startup fails otherwise. |
| `CertificateAuthority` | Let's Encrypt | The ACME directory URL. |
| `Profile` | *(none)* | Certificate profile to request, e.g. `shortlived`. |
| `KeyAlgorithm` | `EcdsaP256` | Key type for issued certificates. |
| `StorageDirectory` | local app data | Where certificates and the account key live. |
| `ExternalAccountBinding` | *(none)* | Required by ZeroSSL and Google Trust Services. |
| `DnsChallengeProvider` | *(none)* | Publishes TXT records for `dns-01`. |
| `PreferredChallengeType` | `http-01` | `http-01` or `dns-01`. |
| `DnsPropagationDelay` | 30s | Wait after publishing a TXT record before asking for validation. |
| `RenewalCheckInterval` | 6h | How often to re-evaluate renewal. |
| `RenewalThreshold` | `1/3` | Fraction of lifetime that must remain, when the authority gives no advice. |
| `UseRenewalInformation` | `true` | Ask the authority when to renew (RFC 9773). |
| `ValidationTimeout` | 5m | How long to wait for a challenge to validate. |
| `PollInterval` | 2s | How often to poll the authority while waiting. |
| `InitialRetryDelay` | 1m | First backoff after a failed order. |
| `MaxRetryDelay` | 6h | Ceiling for that backoff. |
| `ConfigureKestrel` | `true` | Attach the certificate selector to Kestrel's HTTPS defaults. |
| `ServeFallbackCertificate` | `true` | Serve a self-signed certificate until a real one arrives. |
| `HandleHttp01Requests` | `true` | Answer `/.well-known/acme-challenge` from the pipeline. |

## A private, internal or self-hosted authority

Anything reachable over HTTPS that speaks ACME works: step-ca, Smallstep, an internal CA, or
Pebble. Point `CertificateAuthority` at its directory and you are done.

If that authority presents a certificate your machine does not already trust, or if a corporate
proxy inspects TLS on the way out, configure the named `HttpClient` AutoHttps uses to reach it:

```csharp
builder.Services.AddHttpClient(AutoHttpsDefaults.HttpClientName)
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var handler = new SocketsHttpHandler();
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
        {
            // Validate against your own root here rather than accepting everything.
            return errors == System.Net.Security.SslPolicyErrors.None || IsMyInternalCa(certificate);
        };

        return handler;
    });
```

The same registration is the place to add a proxy, a client certificate, or logging handlers. It
only affects traffic to the certificate authority, never the certificates AutoHttps serves.

## Storage

Certificates and the ACME account key are written to `StorageDirectory`, which defaults to
`autohttps` under the user's local application data directory.

> **In a container, point this at a mounted volume.** A storage directory that does not survive a
> restart means a new certificate on every deployment, which will exhaust the authority's rate
> limits. Let's Encrypt allows 5 duplicate certificates per week.

**The directory must be writable by the user the process runs as.** A read-only mount, or a volume
owned by root while the container runs as someone else, means no certificate is ever obtained.
AutoHttps reports that at `Error` (event 122) naming the directory, but it cannot fix it: create the
directory with the right ownership at deploy time rather than relying on the volume default. In
Kubernetes that usually means an `fsGroup`.

A certificate and its key are written to temporary files first and only published once both have
been written, so a volume that fills up mid-write leaves the previous pair intact rather than a
certificate with no key. Files are `0600` on Unix. Certificates for domains you stop using are not
deleted; prune the directory yourself if that matters.

To store certificates elsewhere
(a database, Key Vault, a Kubernetes secret), implement `ICertificateStore` and `IAccountKeyStore`:

```csharp
builder.Services
    .AddAutoHttps(options => { /* ... */ })
    .PersistCertificatesTo<MyCertificateStore>()
    .PersistAccountKeyTo<MyAccountKeyStore>();
```

## Which certificate is served

AutoHttps answers only for the names it manages. For everything else it defers to whatever the
application configured, so adding it to a server that already serves TLS does not disturb what was
there. The matching rules:

- A `*.example.com` entry matches exactly one label: `www.example.com` yes, `a.b.example.com` no,
  and the apex `example.com` no. List the apex separately if you need it.
- Matching ignores case and a trailing dot, so `WWW.Example.com.` matches.
- A request for a name AutoHttps does not manage falls through to the application's own certificate,
  and is refused only when there is none. The same applies to a request carrying no server name.

## Wildcards and DNS challenges

A wildcard certificate can only be validated by `dns-01`, so it needs a provider that can publish
TXT records in your zone:

```csharp
builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add("*.example.com");
    options.DomainNames.Add("example.com");
    options.EmailAddress = "admin@example.com";
    options.AcceptTermsOfService = true;

    options.DnsChallengeProvider = new DelegateDnsChallengeProvider(
        (name, value, ct) => myDnsApi.CreateTxtAsync(name, value, ct),
        (name, value, ct) => myDnsApi.DeleteTxtAsync(name, value, ct));
});
```

Or register a class with `UseDnsChallengeProvider<T>()`. Set
`options.PreferredChallengeType = "dns-01"` to use DNS for every domain, which is the answer when
port 80 is not reachable.

Authorizations are settled one at a time and each record is withdrawn before the next is published,
so a provider that can only hold one value per record name still works.

## Running behind a proxy

A proxy in front of the application is fine. What matters is that Kestrel still terminates TLS and
that the challenge path reaches it. All of these were measured against a real ACME server:

| The proxy does | Challenge works | Certificate is actually used | Verdict |
|---|---|---|---|
| TCP passthrough of 443 (nginx `stream`, HAProxy `mode tcp`, SNI routing) | yes | yes | **recommended** |
| Forwards `/.well-known/acme-challenge` on 80, passes 443 through | yes | yes | **recommended** |
| Rewrites the `Host` header, forwards to a different internal port | yes | yes | fine, the responder ignores host and port |
| Holds its own certificate on 443 | yes | **no** | the certificate is never served; put the ACME client on the proxy instead |
| Answers or blocks `/.well-known/acme-challenge` | **no** | n/a | fix the proxy, or switch to `dns-01` |

A TCP passthrough front end needs nothing from AutoHttps:

```nginx
stream {
    server {
        listen 443;
        proxy_pass app:443;
    }
}
```

The challenge responder matches on the token alone. It does not care what `Host` header arrives or
which port Kestrel is listening on, so a proxy that rewrites either still works.

### When validation fails

The failure message (event 110) names the cause. The authority's own words are quoted, and AutoHttps
adds what only it can know:

| The message contains | What is wrong |
|---|---|
| `could not resolve URL` | the domain has no A or AAAA record |
| `dial tcp <ip>:<port>: connect:` | the name resolves to `<ip>` but nothing there accepts the connection: wrong record, or a firewall |
| `returned 404`, followed by event 127 naming a proxy | something in front of the application answered instead of it: a proxy, ingress or CDN is intercepting the challenge path |
| `key authorization file ... did not match` | the domain points at a different server; the message quotes what came back |

Fixing the cause is enough. AutoHttps retries on its own schedule and picks the fix up without a
restart.

## Running several instances

Instances that share a storage directory coordinate automatically: one takes a lock and orders the
certificate, the rest pick it up from the store and never order their own. That part works, and it
survives the lock holder being killed mid-order. When instances do not share a filesystem, supply
your own lock:

```csharp
builder.Services
    .AddAutoHttps(options => { /* ... */ })
    .UseDistributedLock<MyRedisLock>();
```

> **With `http-01`, replicas behind a single DNS name need care.** The instance that wins the lock is
> not necessarily the one the certificate authority's validation request reaches. Only the winner
> knows the challenge response, so a request landing on any other replica gets a 404 and that
> authorization fails. The order is retried and eventually succeeds, but each miss spends one of the
> authority's failed-validation attempts (Let's Encrypt allows five per account, per hostname, per
> hour), and it repeats at every renewal. Measured with three replicas: eight failed validations to
> issue one certificate.
>
> Pick one of these:
> - **Use `dns-01`.** The challenge never touches the replicas, so the problem disappears entirely.
>   This is the recommended option for anything scaled horizontally.
> - **Route `/.well-known/acme-challenge` to a single replica** at your load balancer.
> - **Run one instance** that owns certificates and share the store with the rest read-only.

## Sending the full chain

By default AutoHttps attaches a certificate selector to Kestrel's HTTPS defaults. Kestrel ignores a
configured certificate chain whenever a selector is in use, so that path can only present the leaf
certificate. Clients that do not already hold the issuing intermediate will reject it.

To send the chain the authority actually issued, opt the endpoint in explicitly:

```csharp
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(80);
    kestrel.ListenAnyIP(443, listen => listen.UseAutoHttps(kestrel.ApplicationServices));
});
```

This builds a per-connection `SslStreamCertificateContext` from the issued chain, keeps HTTP/2
negotiation intact, and is the recommended configuration for anything public. Kestrel drives such an
endpoint from a handshake callback, which it deliberately keeps out of `ConfigureHttpsDefaults`, so
anything else the endpoint needs (a longer `HandshakeTimeout`, client certificates) has to be set
on the overload that takes a callback:

```csharp
kestrel.ListenAnyIP(443, listen => listen.UseAutoHttps(
    kestrel.ApplicationServices,
    tls => tls.HandshakeTimeout = TimeSpan.FromSeconds(30)));
```
 Leaving
`ConfigureKestrel` at its default is fine: an endpoint configured this way overrides the HTTPS
default. Set `ConfigureKestrel = false` only if you want AutoHttps to touch nothing it was not
explicitly asked to.

> **This problem is invisible on Windows, and real on Linux.** Measured against Let's Encrypt's
> Pebble server from a Linux client holding only the issuing root:
>
> | Endpoint configuration | Result |
> |---|---|
> | `listen.UseAutoHttps(services)` | chain verified |
> | automatic wiring (selector only) | **connection rejected** |
>
> On Windows both appear to work, because CryptoAPI caches intermediates it has seen before and
> rebuilds the chain from its own store regardless of what the server sent. A configuration that
> looks correct on a Windows developer machine therefore still fails for clients of the same
> application in a Linux container.
>
> AutoHttps logs a warning (event 126) the first time it serves a certificate whose intermediates it
> cannot send, so this does not stay silent. Using `UseAutoHttps` on the endpoint removes the
> problem entirely.

## Before the first certificate arrives

Obtaining a certificate requires the server to already be listening, so there is a window at first
start where no real certificate exists. AutoHttps serves a self-signed certificate for the
configured domains during that window, so TLS clients see a certificate warning rather than a
connection failure. Requests for names you have not configured are refused rather than answered with
the wrong certificate. Set `ServeFallbackCertificate = false` to turn this off.

## Failure behaviour

Certificate management never takes the application down. Failed orders are retried with exponential
backoff between `InitialRetryDelay` and `MaxRetryDelay`; a store that cannot be written is logged and
the certificate stays in use; an unexpected error is logged and retried. When the authority answers
with a rate limit and a `Retry-After`, that instruction wins over the local backoff. AutoHttps paces
its polling the same way: while an order or authorization is still validating, it waits as long as a
`Retry-After` on the poll asks for rather than checking on a fixed schedule. The application keeps
serving whatever certificate it already holds.

Log categories all begin with `AutoHttps` and event IDs are stable, so they are safe to alert on.
Every event at `Information` and above is listed here; anything not in this table is `Debug` and
exists for diagnosis, not alerting.

| Event | Level | Meaning |
|---|---|---|
| 105 | Information | An order has started. |
| 107 | Information | A certificate was issued. |
| 108 | Information | A stored certificate was loaded at startup. |
| 109 | Information | When the current certificate will be renewed. |
| 116 | Information | The service started and is managing these domains. |
| 120 | Information | A certificate published by another instance was picked up. |
| 110 | Warning | An order failed and will be retried. The reason is in the message; the stack trace is logged separately at Debug as event 124. |
| 112 | Warning | A self-signed fallback is being served, logged once rather than per handshake. |
| 114 | Warning | The store could not be read; continuing without a cached certificate. |
| 115 | Warning | The issued certificate could not be saved. It is in use but will not survive a restart. |
| 118 | Warning | A challenge response could not be withdrawn after validation. |
| 121 | Warning | A freshly issued certificate already qualifies for renewal, so ordering was held off. Check `RenewalThreshold`. |
| 123 | Warning | The authority applied a rate limit. |
| 125 | Warning | The authority stopped recognising the account, so it is being registered again. |
| 126 | Warning | A certificate is being served without its intermediates. See "Sending the full chain". |
| 127 | Warning | A challenge failed and nothing ever requested the response from this process. The message names the cause the authority reported: a name that did not resolve, a connection it could not make, or something in front of the application answering the challenge path. |
| 122 | Error | Something unexpected went wrong, including a storage directory that cannot be written. The application keeps running. |

If you alert on one thing, alert on **110** and **122**. There is no health endpoint or metrics
surface yet, so a certificate expiry monitor pointed at your own domain remains the honest
backstop.

AutoHttps reaches the authority through a named `HttpClient`, and `IHttpClientFactory` logs every
request at Information under `System.Net.Http.HttpClient.AutoHttps.Acme`. If that is noisier than
you want, turn it down without affecting AutoHttps' own logging:

```json
{ "Logging": { "LogLevel": { "System.Net.Http.HttpClient.AutoHttps.Acme": "Warning" } } }
```

## Not in scope

- **`tls-alpn-01`.** .NET does not surface the client's ALPN list to the certificate selection
  callback, so a correct implementation has to parse the raw TLS ClientHello. Until that is done
  properly, `http-01` and `dns-01` cover every scenario `tls-alpn-01` would, provided either port 80
  or your DNS is reachable.
- **Servers other than Kestrel.** IIS and HTTP.sys manage certificates through the operating system.
- **Terminating proxies.** If something else terminates TLS, put an ACME client there instead.
  AutoHttps will happily obtain and renew a certificate in that setup and report success, because
  nothing tells it that the certificate it holds is never the one clients see. It cannot detect this
  for you, so check what your edge actually serves.

## Building and testing

```
dotnet build
dotnet test test/AutoHttps.Tests test/AutoHttps.IntegrationTests
```

The integration tests run against an in-process ACME certificate authority that verifies JWS
signatures, enforces single-use nonces and the exact headers RFC 8555 requires, validates challenges
by actually fetching the URL or reading the TXT record, and issues certificates from a real
throwaway CA. They complete genuine TLS handshakes against the running server and validate the
presented chain.

A second suite runs against [Pebble](https://github.com/letsencrypt/pebble), the test server
Let's Encrypt builds alongside Boulder, so the client is also checked against an implementation
nobody here wrote:

```
docker compose -f test/pebble/docker-compose.yml up -d
dotnet test test/AutoHttps.PebbleTests
```

Pebble is left at its defaults, which means it rejects 5% of otherwise good nonces and reuses
authorizations half the time. The unit and integration suites run on both .NET 8 and .NET 10; the
Pebble suite runs on .NET 10.

## License

MIT. See [LICENSE](https://github.com/astralmaster/AutoHttps/blob/main/LICENSE).
