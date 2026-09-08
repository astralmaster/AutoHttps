namespace AutoHttps.Azure;

/// <summary>
/// Configures the Azure DNS challenge provider. Credentials default to
/// <c>DefaultAzureCredential</c> unless the client-secret fields are all set.
/// </summary>
public sealed class AzureDnsOptions
{
    /// <summary>The subscription the DNS zone is in.</summary>
    public string? SubscriptionId { get; set; }

    /// <summary>The resource group the DNS zone is in.</summary>
    public string? ResourceGroupName { get; set; }

    /// <summary>The DNS zone name, for example <c>example.com</c>. Every validated domain must be in it.</summary>
    public string? ZoneName { get; set; }

    /// <summary>The TTL, in seconds, for the challenge records. Defaults to 60.</summary>
    public int RecordTtlSeconds { get; set; } = 60;

    /// <summary>The tenant id, for an explicit client-secret credential.</summary>
    public string? TenantId { get; set; }

    /// <summary>The client (application) id, for an explicit client-secret credential.</summary>
    public string? ClientId { get; set; }

    /// <summary>The client secret, for an explicit client-secret credential.</summary>
    public string? ClientSecret { get; set; }
}
