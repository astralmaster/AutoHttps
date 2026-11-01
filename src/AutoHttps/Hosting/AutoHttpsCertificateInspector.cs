using System;
using System.Collections.Generic;

namespace AutoHttps.Hosting;

internal sealed class AutoHttpsCertificateInspector : IAutoHttpsCertificateInspector
{
    private static readonly IReadOnlyList<string> NoNames = [];

    private readonly AutoHttpsState _state;
    private readonly Func<string?> _accountUrl;

    public AutoHttpsCertificateInspector(AutoHttpsState state, AcmeSession session)
        : this(state, () => session.AccountUrl)
    {
    }

    internal AutoHttpsCertificateInspector(AutoHttpsState state, Func<string?>? accountUrl = null)
    {
        _state = state;
        _accountUrl = accountUrl ?? (static () => null);
    }

    public AutoHttpsCertificateStatus GetStatus()
    {
        AutoHttpsState.Snapshot snapshot = _state.Current;
        CertificateInfo? certificate = snapshot.Certificate;

        return new AutoHttpsCertificateStatus(
            snapshot.Domains,
            certificate is not null,
            certificate?.SubjectNames ?? NoNames,
            certificate?.NotBefore,
            certificate?.NotAfter,
            certificate?.Thumbprint,
            snapshot.RenewalScheduledAt,
            snapshot.ConsecutiveFailures,
            snapshot.LastFailureAt,
            snapshot.LastFailureReason,
            _accountUrl() is { } accountUrl ? new Uri(accountUrl) : null);
    }
}
