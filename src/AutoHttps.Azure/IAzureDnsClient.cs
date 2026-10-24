using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Azure;

/// <summary>
/// The slice of Azure DNS the provider uses. Keeping the SDK behind this seam lets the provider's own
/// logic be tested without a live subscription.
/// </summary>
internal interface IAzureDnsClient
{
    /// <summary>The TXT record set at <paramref name="relativeRecordName"/>, or null if there is none.</summary>
    Task<AzureTxtRecordSet?> GetTxtAsync(string relativeRecordName, CancellationToken cancellationToken);

    /// <summary>
    /// Writes the record set with these records, but only if nobody changed it since it was read: with
    /// an <paramref name="etag"/> the set must still carry it, and without one there must be no set yet.
    /// Returns false when that condition failed.
    /// </summary>
    Task<bool> TryWriteTxtAsync(
        string relativeRecordName,
        long ttl,
        IReadOnlyList<IReadOnlyList<string>> records,
        string? etag,
        CancellationToken cancellationToken);

    /// <summary>
    /// Deletes the record set, but only if it still carries <paramref name="etag"/>. Returns false when
    /// it changed since it was read, and true when it is gone either way.
    /// </summary>
    Task<bool> TryDeleteTxtAsync(string relativeRecordName, string etag, CancellationToken cancellationToken);
}

/// <summary>
/// A TXT record set as Azure DNS holds it. Each record is a list of strings that together make up its
/// value, because a TXT value longer than 255 characters is stored in pieces.
/// </summary>
internal sealed record AzureTxtRecordSet(long Ttl, IReadOnlyList<IReadOnlyList<string>> Records, string ETag);
