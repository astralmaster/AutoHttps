namespace AutoHttps.Cloudflare;

/// <summary>
/// Configures the Cloudflare DNS challenge provider.
/// </summary>
public sealed class CloudflareDnsOptions
{
    /// <summary>
    /// A Cloudflare API token with permission to edit DNS for the zones being validated. Create a
    /// scoped token with the "Zone.DNS Edit" permission rather than using a global API key.
    /// </summary>
    public string ApiToken { get; set; } = string.Empty;

    /// <summary>
    /// The zone identifier to publish records in. Leave <see langword="null"/> to have the provider
    /// find the zone from the record name, which needs the token to be able to list zones.
    /// </summary>
    public string? ZoneId { get; set; }

    /// <summary>The TTL, in seconds, for the challenge records. Defaults to 60.</summary>
    public int RecordTtlSeconds { get; set; } = 60;
}
