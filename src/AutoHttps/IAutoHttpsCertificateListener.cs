using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps;

/// <summary>
/// Why a certificate became the one being served.
/// </summary>
public enum CertificateChangeReason
{
    /// <summary>The first certificate this instance obtained for the domains.</summary>
    Issued,

    /// <summary>A replacement obtained because the previous certificate was due for renewal.</summary>
    Renewed,

    /// <summary>A certificate another instance obtained, picked up from the shared store.</summary>
    Adopted,
}

/// <summary>
/// The certificate that has just started being served, passed to
/// <see cref="IAutoHttpsCertificateListener.OnCertificateChangedAsync"/>.
/// </summary>
public sealed class CertificateChangedContext
{
    internal CertificateChangedContext(
        IReadOnlyList<string> domains,
        IReadOnlyList<string> subjectNames,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string thumbprint,
        CertificateChangeReason reason)
    {
        Domains = domains;
        SubjectNames = subjectNames;
        NotBefore = notBefore;
        NotAfter = notAfter;
        Thumbprint = thumbprint;
        Reason = reason;
    }

    /// <summary>The domains AutoHttps is managing.</summary>
    public IReadOnlyList<string> Domains { get; }

    /// <summary>The subject alternative names on the new certificate.</summary>
    public IReadOnlyList<string> SubjectNames { get; }

    /// <summary>When the new certificate becomes valid.</summary>
    public DateTimeOffset NotBefore { get; }

    /// <summary>When the new certificate expires.</summary>
    public DateTimeOffset NotAfter { get; }

    /// <summary>The SHA-1 thumbprint of the new leaf certificate.</summary>
    public string Thumbprint { get; }

    /// <summary>Why the certificate changed.</summary>
    public CertificateChangeReason Reason { get; }
}

/// <summary>
/// The order attempt that failed, passed to
/// <see cref="IAutoHttpsCertificateListener.OnCertificateFailedAsync"/>.
/// </summary>
public sealed class CertificateFailedContext
{
    internal CertificateFailedContext(IReadOnlyList<string> domains, string reason, Exception exception)
    {
        Domains = domains;
        Reason = reason;
        Exception = exception;
    }

    /// <summary>The domains AutoHttps is managing.</summary>
    public IReadOnlyList<string> Domains { get; }

    /// <summary>The reason the attempt failed, the same sentence written to the log.</summary>
    public string Reason { get; }

    /// <summary>The exception that ended the attempt.</summary>
    public Exception Exception { get; }
}

/// <summary>
/// Reacts to certificate changes and failures: reload a proxy, copy the certificate somewhere else,
/// warm a cache, or notify an operator. Register one with
/// <see cref="IAutoHttpsBuilder.AddCertificateListener{TListener}()"/>.
/// </summary>
/// <remarks>
/// Both callbacks are awaited on the renewal loop, so a listener that blocks holds up the next
/// renewal check. Keep them quick. An exception thrown by a listener is logged (event 129) and does
/// not affect the certificate, which is already saved and in use by the time a change is reported.
/// A change is reported only when the served certificate actually changes, never once per renewal
/// check, so a reload runs only when there is something new to reload.
/// </remarks>
public interface IAutoHttpsCertificateListener
{
    /// <summary>Called after a new certificate has been saved and is being served.</summary>
    /// <param name="context">The certificate that changed.</param>
    /// <param name="cancellationToken">Signals that the host is shutting down.</param>
    Task OnCertificateChangedAsync(CertificateChangedContext context, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    /// <summary>Called after an order attempt fails. The attempt is retried on the usual backoff.</summary>
    /// <param name="context">The failed attempt.</param>
    /// <param name="cancellationToken">Signals that the host is shutting down.</param>
    Task OnCertificateFailedAsync(CertificateFailedContext context, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
