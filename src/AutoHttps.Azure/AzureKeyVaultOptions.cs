using System;

namespace AutoHttps.Azure;

/// <summary>
/// Configures the Key Vault certificate and account key stores. Credentials default to
/// <c>DefaultAzureCredential</c> unless the client-secret fields are all set.
/// </summary>
public sealed class AzureKeyVaultOptions
{
    /// <summary>The vault URI, for example <c>https://myvault.vault.azure.net/</c>.</summary>
    public Uri? VaultUri { get; set; }

    /// <summary>
    /// A prefix for every secret name AutoHttps writes. Key Vault secret names allow only letters,
    /// digits and hyphens, so the prefix must too. Defaults to <c>autohttps-</c>.
    /// </summary>
    public string SecretPrefix { get; set; } = "autohttps-";

    /// <summary>The tenant id, for an explicit client-secret credential.</summary>
    public string? TenantId { get; set; }

    /// <summary>The client (application) id, for an explicit client-secret credential.</summary>
    public string? ClientId { get; set; }

    /// <summary>The client secret, for an explicit client-secret credential.</summary>
    public string? ClientSecret { get; set; }
}
