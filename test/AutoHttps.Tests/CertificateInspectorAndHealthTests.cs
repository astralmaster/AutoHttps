using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.Hosting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public class CertificateInspectorAndHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void TheInspectorReportsNoCertificateBeforeOneIsObtained()
    {
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);
        var inspector = new AutoHttpsCertificateInspector(state);

        AutoHttpsCertificateStatus status = inspector.GetStatus();

        Assert.False(status.HasCertificate);
        Assert.Empty(status.SubjectNames);
        Assert.Null(status.NotAfter);
        Assert.Equal(["app.example.com"], status.Domains.ToArray());
    }

    [Fact]
    public void TheInspectorReflectsTheServedCertificate()
    {
        var time = new FakeTimeProvider(Now);
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);
        state.RenewalScheduled(Now.AddDays(20));

        using ServerCertificate certificate = SelfSigned("app.example.com", time, TimeSpan.FromDays(30));
        state.CertificatePublished(certificate);

        AutoHttpsCertificateStatus status = new AutoHttpsCertificateInspector(state).GetStatus();

        Assert.True(status.HasCertificate);
        Assert.Equal(["app.example.com"], status.SubjectNames.ToArray());
        Assert.Equal(certificate.Leaf.Thumbprint, status.Thumbprint);
        Assert.Equal(certificate.NotAfter, status.NotAfter);
        Assert.Equal(Now.AddDays(20), status.RenewalScheduledAt);
    }

    [Fact]
    public async Task TheHealthCheckIsHealthyWhileAValidCertificateIsServed()
    {
        HealthCheckResult result = await CheckAsync(TimeSpan.FromDays(30), nearExpiry: TimeSpan.FromDays(7));
        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task TheHealthCheckDegradesWhenTheCertificateIsCloseToExpiry()
    {
        HealthCheckResult result = await CheckAsync(TimeSpan.FromDays(3), nearExpiry: TimeSpan.FromDays(7));
        Assert.Equal(HealthStatus.Degraded, result.Status);
    }

    [Fact]
    public async Task TheHealthCheckIsUnhealthyOnceTheCertificateHasExpired()
    {
        var time = new FakeTimeProvider(Now);
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);

        using ServerCertificate certificate = SelfSigned("app.example.com", time, TimeSpan.FromDays(1));
        state.CertificatePublished(certificate);

        // The certificate keeps being served after it expires, because ordering a replacement may be
        // failing; the health check is exactly how an operator learns that is happening.
        time.Advance(TimeSpan.FromDays(2));

        var check = new AutoHttpsHealthCheck(state, time, HealthStatus.Degraded, TimeSpan.Zero);
        HealthCheckResult result = await check.CheckHealthAsync(new HealthCheckContext(), CancellationToken.None);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
    }

    [Fact]
    public async Task TheHealthCheckReportsTheConfiguredStatusWhileNoCertificateExists()
    {
        var time = new FakeTimeProvider(Now);
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);

        var degraded = new AutoHttpsHealthCheck(state, time, HealthStatus.Degraded, TimeSpan.Zero);
        var unhealthy = new AutoHttpsHealthCheck(state, time, HealthStatus.Unhealthy, TimeSpan.Zero);

        Assert.Equal(
            HealthStatus.Degraded,
            (await degraded.CheckHealthAsync(new HealthCheckContext(), CancellationToken.None)).Status);
        Assert.Equal(
            HealthStatus.Unhealthy,
            (await unhealthy.CheckHealthAsync(new HealthCheckContext(), CancellationToken.None)).Status);
    }

    private static async Task<HealthCheckResult> CheckAsync(TimeSpan lifetime, TimeSpan nearExpiry)
    {
        var time = new FakeTimeProvider(Now);
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);

        using ServerCertificate certificate = SelfSigned("app.example.com", time, lifetime);
        state.CertificatePublished(certificate);

        var check = new AutoHttpsHealthCheck(state, time, HealthStatus.Degraded, nearExpiry);
        return await check.CheckHealthAsync(new HealthCheckContext(), CancellationToken.None);
    }

    private static ServerCertificate SelfSigned(string name, FakeTimeProvider time, TimeSpan lifetime)
    {
        X509Certificate2 leaf = CertificateFactory.CreateSelfSigned([name], time.GetUtcNow(), lifetime);
        return new ServerCertificate(leaf, new X509Certificate2Collection());
    }
}
