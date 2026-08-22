# Migrating from LettuceEncrypt

LettuceEncrypt was archived in April 2025, and its last release targets .NET 6. AutoHttps covers the
same in-process case: your ASP.NET Core app obtains and renews its own certificate while Kestrel
terminates TLS. The setup is close enough that most migrations are a few lines.

## Registration

LettuceEncrypt:

```csharp
builder.Services.AddLettuceEncrypt();
```

AutoHttps takes the settings inline rather than from a separate configuration section:

```csharp
builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add("example.com");
    options.DomainNames.Add("www.example.com");
    options.EmailAddress = "admin@example.com";
    options.AcceptTermsOfService = true;
});
```

Binding from configuration still works if you prefer it:

```csharp
builder.Services.AddAutoHttps(builder.Configuration.GetSection("AutoHttps"));
```

## Option mapping

The three required settings keep the same names, so a `LettuceEncrypt` configuration section moves
across unchanged once you rename it to `AutoHttps`.

| LettuceEncrypt | AutoHttps |
|---|---|
| `DomainNames` | `DomainNames` |
| `EmailAddress` | `EmailAddress` |
| `AcceptTermsOfService` | `AcceptTermsOfService` |
| `UseStagingServer = true` | `CertificateAuthority = CertificateAuthorities.LetsEncryptStaging` |
| `.PersistDataToDirectory(dir, password)` | `options.StorageDirectory = dir` |

## Storage

LettuceEncrypt encrypts its saved data with a password you pass to `PersistDataToDirectory`. AutoHttps
writes the certificate and account key to `StorageDirectory` as plain PEM, and on Unix it sets the key
file to `0600`. Point `StorageDirectory` at a durable, private location (a mounted volume in a
container), and the password argument is gone.

If you persisted to Azure Key Vault through `PersistCertificatesToAzureKeyVault`, AutoHttps has no
built-in Key Vault provider, but its stores are pluggable. Implement `ICertificateStore` and
`IAccountKeyStore` and register them:

```csharp
builder.Services
    .AddAutoHttps(options => { /* ... */ })
    .PersistCertificatesTo<MyCertificateStore>()
    .PersistAccountKeyTo<MyAccountKeyStore>();
```

## Kestrel

LettuceEncrypt asks you to wire it into the HTTPS defaults with `UseLettuceEncrypt`. AutoHttps attaches
to Kestrel on its own, so you can delete that call. To send the full issued chain to clients, which
matters on Linux because the operating system does not fill in intermediates the way Windows does, opt
the endpoint in:

```csharp
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(80);
    kestrel.ListenAnyIP(443, listen => listen.UseAutoHttps(kestrel.ApplicationServices));
});
```

## What changes underneath

Two things differ from LettuceEncrypt, and both are the reason for moving. AutoHttps has no NuGet
dependencies, and it renews on the schedule the authority publishes through ACME Renewal Information
(RFC 9773) rather than a fixed threshold. That is what lets it handle the six-day certificates Let's
Encrypt now issues, through the `Profile` option.

For anything beyond the mapping above, the [README](README.md) has the full option set.
