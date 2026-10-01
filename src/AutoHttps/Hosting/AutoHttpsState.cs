using System;
using System.Collections.Generic;
using AutoHttps.Certificates;

namespace AutoHttps.Hosting;

/// <summary>
/// The certificate state the health check, the inspector and the metrics gauge read. There is a
/// single writer, the <see cref="AutoHttpsService"/> loop, and several readers on other threads.
/// The snapshot is immutable and replaced as a whole, so a reader always sees a coherent set of
/// fields rather than an update caught half applied.
/// </summary>
internal sealed class AutoHttpsState
{
    private volatile Snapshot _snapshot = Snapshot.Empty;

    public Snapshot Current => _snapshot;

    public void SetDomains(IReadOnlyList<string> domains) =>
        _snapshot = _snapshot with { Domains = domains };

    public void CertificatePublished(ServerCertificate certificate) =>
        _snapshot = _snapshot with { Certificate = CertificateInfo.From(certificate) };

    public void RenewalScheduled(DateTimeOffset renewAt) =>
        _snapshot = _snapshot with { RenewalScheduledAt = renewAt };

    public void OrderFailed(DateTimeOffset at, string reason) =>
        _snapshot = _snapshot with
        {
            LastFailureAt = at,
            LastFailureReason = reason,
            ConsecutiveFailures = _snapshot.ConsecutiveFailures + 1,
        };

    /// <summary>
    /// Ends the current run of failures. A single failure says little; a run of them that outlasts
    /// the renewal runway is what the health check and the overdue warning report, so the count has
    /// to be cleared the moment a certificate is in hand again, whether this instance ordered it or
    /// picked it up from another.
    /// </summary>
    public void OrderSucceeded() => _snapshot = _snapshot with { ConsecutiveFailures = 0 };

    internal sealed record Snapshot(
        IReadOnlyList<string> Domains,
        CertificateInfo? Certificate,
        DateTimeOffset? RenewalScheduledAt,
        DateTimeOffset? LastFailureAt,
        string? LastFailureReason,
        int ConsecutiveFailures)
    {
        public static readonly Snapshot Empty = new([], null, null, null, null, 0);
    }
}

internal sealed record CertificateInfo(
    IReadOnlyList<string> SubjectNames,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string Thumbprint)
{
    public static CertificateInfo From(ServerCertificate certificate) => new(
        certificate.SubjectNames,
        certificate.NotBefore,
        certificate.NotAfter,
        certificate.Leaf.Thumbprint);
}
