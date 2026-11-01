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

This replaces the certificate store, the account key store, the `http-01` challenge store and the
lock that stops instances ordering at once. Certificates are written as a hash under
`autohttps:cert:<name>`, the account key under `autohttps:account:<name>`, a pending challenge answer
under `autohttps:challenge:<token>`, and the lock under `autohttps:lock:<name>`. Change the prefix if
you share the Redis with other things:

```csharp
.UseRedis("localhost:6379", options => options.KeyPrefix = "myapp:autohttps:");
```

If your application already registers an `IConnectionMultiplexer`, that one is used and the connection
string here is ignored.

The application starts even when Redis cannot be reached: unless the connection string sets
`abortConnect` itself, the connection is retried in the background, and AutoHttps treats a store it
cannot reach as a failed attempt and tries again.

## Coordinating instances

Instances sharing a certificate also share its renewal time, so without a shared lock they would all
order at the same moment. The lock is a key set only if absent, with a lease the holder renews while
its order runs, so an instance that dies holding it keeps the others waiting for one lease at most
(`LockLease`, a minute by default). A holder that loses its lease while still holding the lock, through a
Redis outage longer than the lease, an eviction or a failover, logs a warning (event 160) and stops
renewing it, because another instance may be ordering the same certificate by then. To use a lock of
your own instead, call `UseDistributedLock<T>()` after `UseRedis`.

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
| `LockLease` | 1 minute | How long the lock survives without renewal, which bounds how long a crashed holder blocks the others. Renewed every third of this while held. |
