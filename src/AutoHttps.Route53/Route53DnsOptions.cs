namespace AutoHttps.Route53;

/// <summary>
/// Configures the Route 53 DNS challenge provider. Credentials and region follow the AWS SDK's usual
/// resolution (environment, shared config, instance role) unless set here.
/// </summary>
public sealed class Route53DnsOptions
{
    /// <summary>
    /// The hosted zone id to publish records in. Leave <see langword="null"/> to find the zone from
    /// the record name, which needs permission to list hosted zones.
    /// </summary>
    public string? HostedZoneId { get; set; }

    /// <summary>An explicit AWS access key id. Leave <see langword="null"/> to use the default credential chain.</summary>
    public string? AccessKeyId { get; set; }

    /// <summary>An explicit AWS secret access key, paired with <see cref="AccessKeyId"/>.</summary>
    public string? SecretAccessKey { get; set; }

    /// <summary>
    /// The AWS region to sign requests for, for example <c>us-east-1</c>. Route 53 is global, but the
    /// SDK still needs a region. Leave <see langword="null"/> to let the SDK resolve one.
    /// </summary>
    public string? Region { get; set; }

    /// <summary>The TTL, in seconds, for the challenge records. Defaults to 60.</summary>
    public int RecordTtlSeconds { get; set; } = 60;
}
