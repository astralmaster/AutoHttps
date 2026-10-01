using System.Collections.Generic;

namespace AutoHttps.Hosting;

internal sealed class AutoHttpsCertificateInspector : IAutoHttpsCertificateInspector
{
    private static readonly IReadOnlyList<string> NoNames = [];

    private readonly AutoHttpsState _state;

    public AutoHttpsCertificateInspector(AutoHttpsState state) => _state = state;

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
            snapshot.LastFailureReason);
    }
}
