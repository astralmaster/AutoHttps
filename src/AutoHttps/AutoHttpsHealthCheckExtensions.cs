using System;
using System.Collections.Generic;
using AutoHttps.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AutoHttps;

/// <summary>
/// Registers a health check that reports on the certificate AutoHttps is serving.
/// </summary>
public static class AutoHttpsHealthCheckExtensions
{
    /// <summary>
    /// Adds a health check for the AutoHttps certificate. It is healthy while a certificate from the
    /// authority is being served, degraded once that certificate is near expiry, unhealthy once it has
    /// expired, and reports <paramref name="missingCertificateStatus"/> before the first one is
    /// obtained. When near expiry coincides with failing renewals, the result says so and carries the
    /// failure count and the last reason.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="name">The name of the health check. Defaults to <c>autohttps</c>.</param>
    /// <param name="missingCertificateStatus">
    /// The status to report while no certificate has been obtained and a self-signed fallback may be
    /// in use. Defaults to <see cref="HealthStatus.Degraded"/>; set it to
    /// <see cref="HealthStatus.Unhealthy"/> to keep the instance out of a load balancer until a real
    /// certificate is in place.
    /// </param>
    /// <param name="nearExpiryWarning">
    /// Report <see cref="HealthStatus.Degraded"/> once the certificate has this long or less left, in
    /// addition to the proportional threshold that is always applied. Off by default: a fixed span
    /// does not suit both 90 day and six day certificates, which is what
    /// <see cref="AutoHttpsOptions.NearExpiryWarningFraction"/> is for. When both are set, whichever
    /// comes first wins.
    /// </param>
    /// <param name="tags">
    /// The tags on the health check. Defaults to <c>ready</c>, so it answers a readiness probe
    /// without being pulled into a liveness probe.
    /// </param>
    /// <returns>The builder.</returns>
    public static IHealthChecksBuilder AddAutoHttps(
        this IHealthChecksBuilder builder,
        string name = "autohttps",
        HealthStatus missingCertificateStatus = HealthStatus.Degraded,
        TimeSpan? nearExpiryWarning = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.AddTypeActivatedCheck<AutoHttpsHealthCheck>(
            name,
            failureStatus: null,
            tags: tags ?? ["ready"],
            args: [missingCertificateStatus, nearExpiryWarning ?? TimeSpan.Zero]);
    }
}
