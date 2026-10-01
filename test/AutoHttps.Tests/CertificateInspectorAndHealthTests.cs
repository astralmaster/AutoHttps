using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.Hosting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public class CertificateInspectorAndHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);

    private const double DefaultFraction = 1d / 6d;

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
        Assert.Equal(0, status.ConsecutiveFailures);
        Assert.Null(status.LastFailureAt);
        Assert.Null(status.LastFailureReason);
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
    public void TheInspectorReportsTheRunOfFailures()
    {
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);

        state.OrderFailed(Now, "The authority refused the order.");
        state.OrderFailed(Now.AddMinutes(1), "Connection refused.");

        AutoHttpsCertificateStatus status = new AutoHttpsCertificateInspector(state).GetStatus();

        Assert.Equal(2, status.ConsecutiveFailures);
        Assert.Equal(Now.AddMinutes(1), status.LastFailureAt);
        Assert.Equal("Connection refused.", status.LastFailureReason);
    }

    [Fact]
    public void ACertificateInHandEndsTheRunOfFailures()
    {
        // A replica that picks up a certificate another one published is no longer failing, so the
        // count has to clear even though this instance never completed an order itself.
        var state = new AutoHttpsState();
        state.OrderFailed(Now, "Connection refused.");
        state.OrderFailed(Now.AddMinutes(1), "Connection refused.");

        state.OrderSucceeded();

        AutoHttpsCertificateStatus status = new AutoHttpsCertificateInspector(state).GetStatus();

        Assert.Equal(0, status.ConsecutiveFailures);

        // The last failure itself is kept. It is still the answer to "what went wrong earlier".
        Assert.Equal("Connection refused.", status.LastFailureReason);
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

        HealthCheckResult result = await RunAsync(Check(state, time));

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
    }

    [Fact]
    public async Task TheHealthCheckReportsTheConfiguredStatusWhileNoCertificateExists()
    {
        var time = new FakeTimeProvider(Now);
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);

        Assert.Equal(
            HealthStatus.Degraded,
            (await RunAsync(Check(state, time, missing: HealthStatus.Degraded))).Status);
        Assert.Equal(
            HealthStatus.Unhealthy,
            (await RunAsync(Check(state, time, missing: HealthStatus.Unhealthy))).Status);
    }

    [Fact]
    public async Task TheNearExpiryWindowAppliesWithoutAnAbsoluteThreshold()
    {
        // The reason the proportional threshold can be on by default: nothing is configured here and
        // a certificate with ten days left out of ninety is still reported.
        HealthCheckResult result = await CheckAsync(
            TimeSpan.FromDays(90), nearExpiry: TimeSpan.Zero, elapsed: TimeSpan.FromDays(80));

        Assert.Equal(HealthStatus.Degraded, result.Status);
    }

    [Fact]
    public async Task ACertificateRenewingOnScheduleIsNeverDegraded()
    {
        // At the default RenewalThreshold renewal starts with a third of the lifetime left, and the
        // window is half of that. A certificate being renewed on time never reaches it, which is what
        // makes the default safe to leave on.
        HealthCheckResult result = await CheckAsync(
            TimeSpan.FromDays(90), nearExpiry: TimeSpan.Zero, elapsed: TimeSpan.FromDays(60));

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task TheNearExpiryWindowScalesToAShortLivedCertificate()
    {
        // The same configuration, a 160 hour certificate: 60 hours left is healthy and 20 hours left
        // is not. An absolute threshold chosen for a 90 day certificate would call both of them fine.
        HealthCheckResult healthy = await CheckAsync(
            TimeSpan.FromHours(160), nearExpiry: TimeSpan.Zero, elapsed: TimeSpan.FromHours(100));
        HealthCheckResult degraded = await CheckAsync(
            TimeSpan.FromHours(160), nearExpiry: TimeSpan.Zero, elapsed: TimeSpan.FromHours(140));

        Assert.Equal(HealthStatus.Healthy, healthy.Status);
        Assert.Equal(HealthStatus.Degraded, degraded.Status);
    }

    [Fact]
    public async Task TheDefaultWindowFollowsACustomRenewalThreshold()
    {
        // Renewal here starts with a tenth of the lifetime left, so the window has to move with it.
        // Half of a tenth of 90 days is 4.5 days: six days left is outside it, three days inside.
        // A fixed default of a sixth would have reported Degraded from 15 days out, five days before
        // renewal was even attempted, and never cleared.
        HealthCheckResult outside = await CheckAsync(
            TimeSpan.FromDays(90),
            nearExpiry: TimeSpan.Zero,
            elapsed: TimeSpan.FromDays(84),
            fraction: null,
            renewalThreshold: 0.1);
        HealthCheckResult inside = await CheckAsync(
            TimeSpan.FromDays(90),
            nearExpiry: TimeSpan.Zero,
            elapsed: TimeSpan.FromDays(87),
            fraction: null,
            renewalThreshold: 0.1);

        Assert.Equal(HealthStatus.Healthy, outside.Status);
        Assert.Equal(HealthStatus.Degraded, inside.Status);
    }

    [Fact]
    public async Task TheDefaultWindowIsHalfTheDefaultRenewalThreshold()
    {
        HealthCheckResult outside = await CheckAsync(
            TimeSpan.FromDays(90), nearExpiry: TimeSpan.Zero, elapsed: TimeSpan.FromDays(70), fraction: null);
        HealthCheckResult inside = await CheckAsync(
            TimeSpan.FromDays(90), nearExpiry: TimeSpan.Zero, elapsed: TimeSpan.FromDays(80), fraction: null);

        Assert.Equal(HealthStatus.Healthy, outside.Status);
        Assert.Equal(HealthStatus.Degraded, inside.Status);
    }

    [Fact]
    public async Task AZeroFractionLeavesTheCheckHealthyUntilExpiry()
    {
        HealthCheckResult result = await CheckAsync(
            TimeSpan.FromDays(90),
            nearExpiry: TimeSpan.Zero,
            elapsed: TimeSpan.FromDays(89),
            fraction: 0);

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task AnAbsoluteThresholdStillAppliesWhenItComesFirst()
    {
        // 35 days left of 90 is outside the proportional window of 15 days, so only the absolute
        // threshold can report it. Both are honoured and the earlier one wins.
        HealthCheckResult result = await CheckAsync(
            TimeSpan.FromDays(90), nearExpiry: TimeSpan.FromDays(40), elapsed: TimeSpan.FromDays(55));

        Assert.Equal(HealthStatus.Degraded, result.Status);
    }

    [Fact]
    public async Task AFailingRenewalInsideTheWindowIsReportedAsOverdue()
    {
        var time = new FakeTimeProvider(Now);
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);

        using ServerCertificate certificate = SelfSigned("app.example.com", time, TimeSpan.FromDays(90));
        state.CertificatePublished(certificate);
        time.Advance(TimeSpan.FromDays(80));

        state.OrderFailed(time.GetUtcNow(), "The authority could not reach the challenge path.");
        state.OrderFailed(time.GetUtcNow(), "The authority could not reach the challenge path.");

        HealthCheckResult result = await RunAsync(Check(state, time));

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("overdue", result.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("challenge path", result.Description, StringComparison.Ordinal);
        Assert.Equal(2, result.Data["consecutive_failures"]);
        Assert.Equal(
            "The authority could not reach the challenge path.",
            result.Data["last_failure_reason"]);
    }

    [Fact]
    public async Task ACertificateCloseToExpiryWithoutFailuresIsNotCalledOverdue()
    {
        // Near expiry with nothing failing is a different situation from near expiry because renewal
        // is broken, and the two need different responses.
        HealthCheckResult result = await CheckAsync(
            TimeSpan.FromDays(90), nearExpiry: TimeSpan.Zero, elapsed: TimeSpan.FromDays(80));

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.DoesNotContain("overdue", result.Description, StringComparison.OrdinalIgnoreCase);
        Assert.False(result.Data.ContainsKey("consecutive_failures"));
    }

    [Fact]
    public async Task TheFailureCountIsReportedBeforeTheFirstCertificateExists()
    {
        // The window cannot be computed without a certificate, but a run of failures is still the
        // most useful thing the check can say while the first order keeps failing.
        var time = new FakeTimeProvider(Now);
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);
        state.OrderFailed(Now, "Connection refused.");

        HealthCheckResult result = await RunAsync(Check(state, time));

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Equal(1, result.Data["consecutive_failures"]);
    }

    private static Task<HealthCheckResult> RunAsync(AutoHttpsHealthCheck check) =>
        check.CheckHealthAsync(new HealthCheckContext(), CancellationToken.None);

    private static AutoHttpsHealthCheck Check(
        AutoHttpsState state,
        TimeProvider time,
        HealthStatus missing = HealthStatus.Degraded,
        TimeSpan nearExpiry = default,
        double? fraction = DefaultFraction,
        double renewalThreshold = 1d / 3d) =>
        new(
            state,
            time,
            Options.Create(new AutoHttpsOptions
            {
                NearExpiryWarningFraction = fraction,
                RenewalThreshold = renewalThreshold,
            }),
            missing,
            nearExpiry);

    private static async Task<HealthCheckResult> CheckAsync(
        TimeSpan lifetime,
        TimeSpan nearExpiry,
        TimeSpan elapsed = default,
        double? fraction = DefaultFraction,
        double renewalThreshold = 1d / 3d)
    {
        var time = new FakeTimeProvider(Now);
        var state = new AutoHttpsState();
        state.SetDomains(["app.example.com"]);

        using ServerCertificate certificate = SelfSigned("app.example.com", time, lifetime);
        state.CertificatePublished(certificate);

        if (elapsed > TimeSpan.Zero)
        {
            time.Advance(elapsed);
        }

        return await RunAsync(Check(
            state, time, nearExpiry: nearExpiry, fraction: fraction, renewalThreshold: renewalThreshold));
    }

    private static ServerCertificate SelfSigned(string name, FakeTimeProvider time, TimeSpan lifetime)
    {
        X509Certificate2 leaf = CertificateFactory.CreateSelfSigned([name], time.GetUtcNow(), lifetime);
        return new ServerCertificate(leaf, new X509Certificate2Collection());
    }
}
