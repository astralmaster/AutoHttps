# AutoHttps.Redis

Redis certificate, account key and challenge stores for
[AutoHttps](https://github.com/astralmaster/AutoHttps). Several instances share their certificates,
their ACME registration and their pending `http-01` challenge answers through Redis rather than a
shared filesystem.

```
dotnet add package AutoHttps.Redis
```

## Use

```csharp
builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add("example.com");
    options.EmailAddress = "admin@example.com";
    options.AcceptTermsOfService = true;
})
.UseRedis(builder.Configuration.GetConnectionString("Redis")!);
```

This replaces the certificate store, the account key store and the `http-01` challenge store.
Certificates are written as a hash under `autohttps:cert:<name>`, the account key under
`autohttps:account:<name>`, and a pending challenge answer under `autohttps:challenge:<token>`. Change
the prefix if you share the Redis with other things:

```csharp
.UseRedis("localhost:6379", options => options.KeyPrefix = "myapp:autohttps:");
```

If your application already registers an `IConnectionMultiplexer`, that one is used and the connection
string here is ignored.

## Coordinating instances

Redis holds the certificates, but instances still need a lock so only one orders at a time. Supply one
with `UseDistributedLock<T>()` on the AutoHttps builder. See "Running several instances" in the main
README.

Sharing the challenge store is what lets replicas behind a single DNS name pass an `http-01`
validation. The authority's request lands on whichever replica the load balancer picks, which is not
necessarily the one that ordered, and any of them can then answer it from Redis. Without that, a
request reaching another replica gets a 404 and the authorization fails. If you want Redis for
certificates but not for challenges, register the challenge store yourself with
`UseHttp01ChallengeStore<T>()` after `UseRedis`.

## Options

| Option | Default | What it does |
|---|---|---|
| `Configuration` | *(from the argument)* | StackExchange.Redis connection string. |
| `KeyPrefix` | `autohttps:` | Prefix for every key written. |
| `ChallengeTtl` | 15 minutes | How long a published challenge answer survives if an order is interrupted before removing it. Zero or less keeps it until removed. |
