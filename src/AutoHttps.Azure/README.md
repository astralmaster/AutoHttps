# AutoHttps.Azure

Azure support for [AutoHttps](https://github.com/astralmaster/AutoHttps): `dns-01` challenges through
Azure DNS, and certificate and account key storage in Key Vault. Use either part, or both.

```
dotnet add package AutoHttps.Azure
```

## DNS challenges through Azure DNS

Every validated domain must live in the configured zone.

```csharp
builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add("*.example.com");
    options.DomainNames.Add("example.com");
    options.EmailAddress = "admin@example.com";
    options.AcceptTermsOfService = true;
    options.PreferredChallengeType = "dns-01";
})
.UseAzureDns(dns =>
{
    dns.SubscriptionId = "00000000-0000-0000-0000-000000000000";
    dns.ResourceGroupName = "dns-rg";
    dns.ZoneName = "example.com";
});
```

## Storage in Key Vault

```csharp
builder.Services.AddAutoHttps(options => { /* ... */ })
    .UseAzureKeyVault(vault => vault.VaultUri = new Uri("https://myvault.vault.azure.net/"));
```

Certificates and the account key are stored as secrets. Key Vault names allow only letters, digits
and hyphens, so each store identifier becomes a sanitised name with a hash of the original appended,
which keeps distinct identifiers from colliding.

## Credentials

Both parts use `DefaultAzureCredential` by default, which resolves a managed identity, environment
variables, or the Azure CLI. Set `TenantId`, `ClientId` and `ClientSecret` on the options to use a
service principal instead. The identity needs DNS Zone Contributor on the zone, and Key Vault Secrets
Officer on the vault.

## Options

`AzureDnsOptions`: `SubscriptionId`, `ResourceGroupName`, `ZoneName` (all required), `RecordTtlSeconds`
(default 60), and the credential fields.

`AzureKeyVaultOptions`: `VaultUri` (required), `SecretPrefix` (default `autohttps-`), and the credential
fields.
