using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AutoHttps.Hosting;

internal sealed class AutoHttpsHealthCheck : IHealthCheck
{
    private readonly AutoHttpsState _state;
    private readonly TimeProvider _time;
    private readonly HealthStatus _missingCertificateStatus;
    private readonly TimeSpan _nearExpiryWarning;

    public AutoHttpsHealthCheck(
        AutoHttpsState state,
        TimeProvider time,
        HealthStatus missingCertificateStatus,
        TimeSpan nearExpiryWarning)
    {
        _state = state;
        _time = time;
        _missingCertificateStatus = missingCertificateStatus;
        _nearExpiryWarning = nearExpiryWarning;
    }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken)
    {
        AutoHttpsState.Snapshot snapshot = _state.Current;
        var data = new Dictionary<string, object>(StringComparer.Ordinal);

        if (snapshot.Domains.Count > 0)
        {
            data["domains"] = string.Join(", ", snapshot.Domains);
        }

        if (snapshot.Certificate is not { } certificate)
        {
            return Task.FromResult(new HealthCheckResult(
                _missingCertificateStatus,
                "AutoHttps has not obtained a certificate yet; a self-signed fallback may be in use.",
                data: data));
        }

        DateTimeOffset now = _time.GetUtcNow();
        TimeSpan remaining = certificate.NotAfter - now;

        data["subject"] = string.Join(", ", certificate.SubjectNames);
        data["not_after"] = certificate.NotAfter.ToString("u", CultureInfo.InvariantCulture);
        data["thumbprint"] = certificate.Thumbprint;
        data["seconds_remaining"] = (long)remaining.TotalSeconds;

        if (remaining <= TimeSpan.Zero)
        {
            return Task.FromResult(new HealthCheckResult(
                HealthStatus.Unhealthy, "The managed certificate has expired.", data: data));
        }

        if (_nearExpiryWarning > TimeSpan.Zero && remaining <= _nearExpiryWarning)
        {
            return Task.FromResult(new HealthCheckResult(
                HealthStatus.Degraded, "The managed certificate is close to expiry.", data: data));
        }

        return Task.FromResult(HealthCheckResult.Healthy("The managed certificate is valid.", data));
    }
}
