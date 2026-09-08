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
    private readonly ILogger<AutoHttpsCertificateManager> _logger;

    public AutoHttpsCertificateManager(
        AcmeSession session,
        CertificateSelector selector,
        AutoHttpsState state,
        ILogger<AutoHttpsCertificateManager> logger)
    {
        _session = session;
        _selector = selector;
        _state = state;
        _logger = logger;
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
