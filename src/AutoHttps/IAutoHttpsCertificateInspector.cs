using System;
using System.Collections.Generic;

namespace AutoHttps;

/// <summary>
/// Reads the certificate AutoHttps is currently managing. Resolve it from the service provider to
/// check, from application code, what is being served and when it will be renewed.
/// </summary>
public interface IAutoHttpsCertificateInspector
{
    /// <summary>Returns a snapshot of the current certificate state.</summary>
    AutoHttpsCertificateStatus GetStatus();
}

/// <summary>
/// A snapshot of what AutoHttps is serving, returned by
/// <see cref="IAutoHttpsCertificateInspector.GetStatus"/>.
/// </summary>
public sealed class AutoHttpsCertificateStatus
{
    internal AutoHttpsCertificateStatus(
        IReadOnlyList<string> domains,
        bool hasCertificate,
        IReadOnlyList<string> subjectNames,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter,
        string? thumbprint,
        DateTimeOffset? renewalScheduledAt)
    {
        Domains = domains;
        HasCertificate = hasCertificate;
        SubjectNames = subjectNames;
        NotBefore = notBefore;
        NotAfter = notAfter;
        Thumbprint = thumbprint;
        RenewalScheduledAt = renewalScheduledAt;
    }

    /// <summary>The domains AutoHttps is managing.</summary>
    public IReadOnlyList<string> Domains { get; }

    /// <summary>
    /// Whether a certificate obtained from the authority is being served. When
    /// <see langword="false"/>, a self-signed fallback may be in use while the first one is obtained.
    /// </summary>
    public bool HasCertificate { get; }

    /// <summary>The subject alternative names on the served certificate, empty when there is none.</summary>
    public IReadOnlyList<string> SubjectNames { get; }

    /// <summary>When the served certificate becomes valid, or <see langword="null"/> when there is none.</summary>
    public DateTimeOffset? NotBefore { get; }

    /// <summary>When the served certificate expires, or <see langword="null"/> when there is none.</summary>
    public DateTimeOffset? NotAfter { get; }

    /// <summary>The SHA-1 thumbprint of the served leaf certificate, or <see langword="null"/> when there is none.</summary>
    public string? Thumbprint { get; }

    /// <summary>
    /// When AutoHttps next plans to renew, or <see langword="null"/> before the first renewal check.
    /// </summary>
    public DateTimeOffset? RenewalScheduledAt { get; }
}
