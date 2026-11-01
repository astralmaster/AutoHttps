using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Certificates;
using AutoHttps.Internal;
using Microsoft.Extensions.Logging;

namespace AutoHttps.Hosting;

internal sealed class AutoHttpsCertificateManager : IAutoHttpsCertificateManager
{
    private readonly AcmeSession _session;
    private readonly CertificateSelector _selector;
    private readonly AutoHttpsState _state;
    private readonly RenewalRequests _requests;
    private readonly ILogger<AutoHttpsCertificateManager> _logger;

    public AutoHttpsCertificateManager(
        AcmeSession session,
        CertificateSelector selector,
        AutoHttpsState state,
        RenewalRequests requests,
        ILogger<AutoHttpsCertificateManager> logger)
    {
        _session = session;
        _selector = selector;
        _state = state;
        _requests = requests;
        _logger = logger;
    }

    public async Task RenewAsync(RevocationReason? revokePrevious = null, CancellationToken cancellationToken = default)
    {
        // Taken before asking, because the certificate is replaced, and later disposed, while this waits.
        ServerCertificate? current = FindCurrent();
        string? replacing = current?.Leaf.Thumbprint;
        byte[]? previous = revokePrevious is not null ? current?.Leaf.RawData : null;

        Task replaced = _requests.RequestAsync(replacing, cancellationToken);

        // A request refused at once, for example because a development certificate is served and
        // nothing is ordered, is not reported as an order starting.
        if (!replaced.IsFaulted)
        {
            string domains = string.Join(", ", _state.Current.Domains);
            Log.RenewalRequested(_logger, domains);
        }

        await replaced;

        if (previous is not null && revokePrevious is { } reason)
        {
            AcmeClient client = await _session.GetClientAsync(requireAccount: true, cancellationToken);

            try
            {
                await client.RevokeCertificateAsync(previous, (int)reason, cancellationToken);
                Log.CertificateRevoked(_logger, replacing!, reason);
            }
            catch (AcmeException ex) when (ex.ErrorType == AcmeErrorTypes.AlreadyRevoked)
            {
                // Calls made together share one order, so they replace the same certificate and every
                // one of them revokes it. The first does, and the rest are told it already is, which is
                // the outcome each of them asked for.
            }
        }
    }

    public async Task RevokeAsync(
        X509Certificate2 certificate,
        RevocationReason reason = RevocationReason.Unspecified,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        AcmeClient client = await _session.GetClientAsync(requireAccount: true, cancellationToken);
        await client.RevokeCertificateAsync(certificate.RawData, (int)reason, cancellationToken);

        Log.CertificateRevoked(_logger, certificate.Thumbprint, reason);
    }

    public async Task<bool> RevokeCurrentAsync(
        RevocationReason reason = RevocationReason.Unspecified,
        CancellationToken cancellationToken = default)
    {
        if (FindCurrent() is not { } current)
        {
            return false;
        }

        await RevokeAsync(current.Leaf, reason, cancellationToken);
        return true;
    }

    private ServerCertificate? FindCurrent()
    {
        foreach (string domain in _state.Current.Domains)
        {
            if (_selector.Find(domain) is { } certificate)
            {
                return certificate;
            }
        }

        return null;
    }
}
