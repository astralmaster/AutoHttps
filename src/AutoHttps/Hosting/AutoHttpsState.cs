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
        _snapshot = _snapshot with { LastFailureAt = at, LastFailureReason = reason };

    internal sealed record Snapshot(
        IReadOnlyList<string> Domains,
        CertificateInfo? Certificate,
        DateTimeOffset? RenewalScheduledAt,
        DateTimeOffset? LastFailureAt,
        string? LastFailureReason)
    {
        public static readonly Snapshot Empty = new([], null, null, null, null);
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
