# AutoHttps.Redis

Redis certificate and account key stores for
[AutoHttps](https://github.com/astralmaster/AutoHttps). Several instances share their certificates and
their ACME registration through Redis rather than a shared filesystem.

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

This replaces both the certificate store and the account key store. Certificates are written as a
hash under `autohttps:cert:<name>` and the account key under `autohttps:account:<name>`. Change the
prefix if you share the Redis with other things:

```csharp
.UseRedis("localhost:6379", options => options.KeyPrefix = "myapp:autohttps:");
```

If your application already registers an `IConnectionMultiplexer`, that one is used and the connection
string here is ignored.

## Coordinating instances

Redis holds the certificates, but instances still need a lock so only one orders at a time. Supply one
with `UseDistributedLock<T>()` on the AutoHttps builder. See "Running several instances" in the main
README.

## Options

| Option | Default | What it does |
|---|---|---|
| `Configuration` | *(from the argument)* | StackExchange.Redis connection string. |
| `KeyPrefix` | `autohttps:` | Prefix for every key written. |
