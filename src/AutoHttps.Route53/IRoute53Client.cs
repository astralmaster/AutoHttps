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

    /// <summary>
    /// Replaces the TXT record set at <paramref name="recordName"/> in one change batch, which Route 53
    /// applies whole or not at all: a DELETE of <paramref name="expected"/> exactly as it was read, when
    /// there was one, then a CREATE of <paramref name="replacement"/>, when there is one. A DELETE that
    /// does not match the set as it now stands, or a CREATE where a set now exists, refuses the batch,
    /// so the write only lands when nobody changed the set since it was read.
    /// </summary>
    /// <returns>The change id, or the reason Route 53 refused the batch.</returns>
    Task<Route53ChangeResult> TryReplaceTxtAsync(
        string zoneId,
        string recordName,
        Route53TxtRecord? expected,
        Route53TxtRecord? replacement,
        CancellationToken cancellationToken);

    /// <summary>Whether Route 53 has applied the change to every name server for the zone (INSYNC).</summary>
    Task<bool> IsChangeInSyncAsync(string changeId, CancellationToken cancellationToken);
}

/// <summary>A TXT record's values, as Route 53 stores them (each already quoted), and its TTL.</summary>
internal sealed record Route53TxtRecord(long Ttl, IReadOnlyList<string> Values);

/// <summary>
/// The outcome of <see cref="IRoute53Client.TryReplaceTxtAsync"/>: the change id when the batch was
/// applied, otherwise Route 53's reason for refusing it.
/// </summary>
internal readonly record struct Route53ChangeResult(string? ChangeId, string? Refusal);
