using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Route53;

/// <summary>
/// The slice of Route 53 the provider uses. Keeping the AWS SDK behind this seam lets the provider's
/// own logic be tested without a live account.
/// </summary>
internal interface IRoute53Client
{
    /// <summary>The id of the public hosted zone whose name is exactly <paramref name="dnsName"/>, or null.</summary>
    Task<string?> FindZoneIdAsync(string dnsName, CancellationToken cancellationToken);

    /// <summary>The current TXT record at <paramref name="recordName"/>, or null if there is none.</summary>
    Task<Route53TxtRecord?> GetTxtRecordAsync(string zoneId, string recordName, CancellationToken cancellationToken);

    /// <summary>Applies a change (<c>UPSERT</c> or <c>DELETE</c>) to the TXT record at <paramref name="recordName"/>.</summary>
    Task ChangeTxtAsync(
        string zoneId,
        string recordName,
        string action,
        long ttl,
        IReadOnlyList<string> values,
        CancellationToken cancellationToken);
}

/// <summary>A TXT record's values, as Route 53 stores them (each already quoted), and its TTL.</summary>
internal sealed record Route53TxtRecord(long Ttl, IReadOnlyList<string> Values);
