using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Azure;

/// <summary>
/// The slice of Azure DNS the provider uses. Keeping the SDK behind this seam lets the provider's own
/// logic be tested without a live subscription.
/// </summary>
internal interface IAzureDnsClient
{
    /// <summary>Creates or replaces the TXT record set at <paramref name="relativeRecordName"/> with one value.</summary>
    Task UpsertTxtAsync(string relativeRecordName, long ttl, string value, CancellationToken cancellationToken);

    /// <summary>Removes the TXT record set at <paramref name="relativeRecordName"/>, or does nothing if it is absent.</summary>
    Task DeleteTxtAsync(string relativeRecordName, CancellationToken cancellationToken);
}
