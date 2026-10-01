using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Renewal;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

internal sealed class AutoHttpsHealthCheck : IHealthCheck
{
    private readonly AutoHttpsState _state;
    private readonly TimeProvider _time;
    private readonly AutoHttpsOptions _options;
    private readonly HealthStatus _missingCertificateStatus;
    private readonly TimeSpan _nearExpiryWarning;

    public AutoHttpsHealthCheck(
        AutoHttpsState state,
        TimeProvider time,
        IOptions<AutoHttpsOptions> options,
        HealthStatus missingCertificateStatus,
        TimeSpan nearExpiryWarning)
    {
        _state = state;
        _time = time;
        _options = options.Value;
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

        AddFailureData(snapshot, data);

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

        if (remaining <= NearExpiryThreshold(certificate))
        {
            return Task.FromResult(new HealthCheckResult(
                HealthStatus.Degraded, DescribeNearExpiry(snapshot), data: data));
        }

        return Task.FromResult(HealthCheckResult.Healthy("The managed certificate is valid.", data));
    }

    /// <summary>
    /// The point at which the certificate counts as near expiry. Both thresholds are honoured and
    /// the earlier one wins: the fraction of lifetime, which is on by default because a certificate
    /// that renews on schedule never reaches it, and the absolute span, which is off unless set.
    /// </summary>
    private TimeSpan NearExpiryThreshold(CertificateInfo certificate)
    {
        TimeSpan relative = RenewalRisk.NearExpiry(
            certificate.NotBefore,
            certificate.NotAfter,
            RenewalRisk.EffectiveNearExpiryFraction(_options.NearExpiryWarningFraction, _options.RenewalThreshold));

        return _nearExpiryWarning > relative ? _nearExpiryWarning : relative;
    }

    /// <summary>
    /// Separates a certificate that is merely close to expiry from one that is close to expiry
    /// because renewal is failing. They need different responses, and the health check is where an
    /// operator sees which one this is.
    /// </summary>
    private static string DescribeNearExpiry(AutoHttpsState.Snapshot snapshot)
    {
        if (snapshot.ConsecutiveFailures <= 0)
        {
            return "The managed certificate is close to expiry.";
        }

        string reason = snapshot.LastFailureReason is { Length: > 0 } last ? " " + last : string.Empty;
        return string.Create(
            CultureInfo.InvariantCulture,
            $"Renewal is overdue: the managed certificate is close to expiry and {snapshot.ConsecutiveFailures} renewal attempts in a row have failed.{reason}");
    }

    private static void AddFailureData(AutoHttpsState.Snapshot snapshot, Dictionary<string, object> data)
    {
        if (snapshot.ConsecutiveFailures <= 0)
        {
            return;
        }

        data["consecutive_failures"] = snapshot.ConsecutiveFailures;

        if (snapshot.LastFailureAt is { } at)
        {
            data["last_failure"] = at.ToString("u", CultureInfo.InvariantCulture);
        }

        if (snapshot.LastFailureReason is { } reason)
        {
            data["last_failure_reason"] = reason;
        }
    }
}
