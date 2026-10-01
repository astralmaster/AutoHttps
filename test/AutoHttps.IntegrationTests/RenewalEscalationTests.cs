using System;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// Covers the difference between a renewal attempt that failed, which is routine and retried, and a
/// renewal that is not going to happen before the certificate expires. Let's Encrypt stopped sending
/// expiry notifications in June 2025, so the only thing that notices a stuck renewal is the process
/// it is stuck in.
/// </summary>
public class RenewalEscalationTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The certificates here live five minutes, and the test authority backdates them by five
    /// seconds, so 295 of the 300 seconds remain at issuance. Renewal is driven by the threshold
    /// rather than the authority's renewal window, which makes the timings exact: renewal is already
    /// due when the certificate arrives, a wide window of 285 seconds is entered ten seconds later,
    /// and a narrow one of 15 seconds is not entered for 280 seconds. Ten seconds of margin on
    /// either side is what keeps these from turning into a race with the certificate's own clock.
    /// </summary>
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private const double DueImmediately = 0.99;
    private const double WideWindow = 0.95;
    private const double NarrowWindow = 0.05;

    /// <summary>The overdue error, the one worth paging on.</summary>
    private const int RenewalOverdue = 147;

    /// <summary>The per-attempt warning, which fires on every failure and is not worth paging on.</summary>
    private const int OrderFailed = 110;

    [Fact]
    public async Task AFailingRenewalInsideTheNearExpiryWindowIsEscalated()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await StartAuthorityAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority, Configure(storage, WideWindow));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        authority.Behavior.FailValidation = true;

        await WaitForEventAsync(app, RenewalOverdue, TimeSpan.FromSeconds(60));

        Assert.True(app.Log.CountOf(OrderFailed) >= 1, app.Log.Describe());
    }

    [Fact]
    public async Task TheOverdueErrorIsLoggedOnceRatherThanOnEveryAttempt()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await StartAuthorityAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority, Configure(storage, WideWindow));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        authority.Behavior.FailValidation = true;

        await WaitForEventAsync(app, RenewalOverdue, TimeSpan.FromSeconds(60));
        await Task.Delay(TimeSpan.FromSeconds(5));

        // An outage lasting days must not produce one error per attempt, which is what would make
        // people mute the event instead of alerting on it.
        Assert.Equal(1, app.Log.CountOf(RenewalOverdue));
        Assert.True(
            app.Log.CountOf(OrderFailed) > 1,
            $"expected repeated per-attempt warnings, saw {app.Log.CountOf(OrderFailed)}");
    }

    [Fact]
    public async Task AFailureWithTheRunwayStillAheadIsNotEscalated()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await StartAuthorityAsync();

        // Identical to the escalating case except for the window: a twentieth of the lifetime is
        // fifteen seconds, so for the whole observation below renewal is failing with the runway
        // still ahead of it. That is the case that has to stay quiet.
        await using TestApplication app = await TestApplication.StartAsync(
            authority, Configure(storage, NarrowWindow));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        authority.Behavior.FailValidation = true;

        await WaitForEventAsync(app, OrderFailed, TimeSpan.FromSeconds(60));
        await Task.Delay(TimeSpan.FromSeconds(10));

        Assert.True(app.Log.CountOf(OrderFailed) > 1, "renewal should have been failing repeatedly");
        Assert.Equal(0, app.Log.CountOf(RenewalOverdue));
    }

    [Fact]
    public async Task TheHealthCheckReportsOverdueWhileRenewalKeepsFailing()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await StartAuthorityAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            Configure(storage, WideWindow),
            // Registered the way an application does it, which is what proves the check can still be
            // built through AddTypeActivatedCheck now that it resolves options from the container.
            configureServices: services => services.AddHealthChecks().AddAutoHttps());

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        HealthReportEntry fresh = await ReadHealthAsync(app);
        Assert.Equal(HealthStatus.Healthy, fresh.Status);

        authority.Behavior.FailValidation = true;
        await WaitForEventAsync(app, RenewalOverdue, TimeSpan.FromSeconds(60));

        HealthReportEntry overdue = await ReadHealthAsync(app);

        Assert.Equal(HealthStatus.Degraded, overdue.Status);
        Assert.Contains("overdue", overdue.Description!, StringComparison.OrdinalIgnoreCase);
        Assert.True((int)overdue.Data["consecutive_failures"] >= 1);
        Assert.True(overdue.Data.ContainsKey("last_failure_reason"));
    }

    [Fact]
    public async Task ASuccessfulRenewalClearsTheOverdueSignal()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await StartAuthorityAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            Configure(storage, WideWindow),
            configureServices: services => services.AddHealthChecks().AddAutoHttps());

        ServerCertificate first = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        authority.Behavior.FailValidation = true;
        await WaitForEventAsync(app, RenewalOverdue, TimeSpan.FromSeconds(60));

        // Fix the cause. The signal has to clear on its own, otherwise an operator cannot tell a
        // recovered instance from one that is still broken.
        authority.Behavior.FailValidation = false;
        await app.WaitForCertificateChangeAsync(
            "app.example.com", first.Leaf.Thumbprint, TimeSpan.FromSeconds(60));

        HealthReportEntry recovered = await ReadHealthAsync(app);

        Assert.False(
            recovered.Data.ContainsKey("consecutive_failures"),
            $"the failure run should have been cleared, saw: {recovered.Description}");
        Assert.DoesNotContain("overdue", recovered.Description!, StringComparison.OrdinalIgnoreCase);

        AutoHttpsCertificateStatus status = app.Services
            .GetRequiredService<IAutoHttpsCertificateInspector>()
            .GetStatus();

        Assert.Equal(0, status.ConsecutiveFailures);

        // The failure itself is kept. It is still the answer to what went wrong earlier.
        Assert.NotNull(status.LastFailureReason);
    }

    private static async Task<TestCertificateAuthority> StartAuthorityAsync()
    {
        TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.CertificateLifetime = Lifetime;

        // Without this the authority's renewal window governs when renewal is due, which for these
        // lifetimes is a few seconds before expiry, and the test would be waiting on the clock
        // rather than on the behaviour under test.
        authority.Behavior.AdvertiseRenewalInfo = false;

        return authority;
    }

    private static Action<AutoHttpsOptions> Configure(TempStorage storage, double nearExpiryFraction) => options =>
    {
        options.DomainNames.Add("app.example.com");
        options.StorageDirectory = storage.Path;
        options.RenewalCheckInterval = TimeSpan.FromMilliseconds(500);
        options.UseRenewalInformation = false;
        options.RenewalThreshold = DueImmediately;
        options.NearExpiryWarningFraction = nearExpiryFraction;

        // Retry fast, so an observation window of a few seconds contains several attempts.
        options.InitialRetryDelay = TimeSpan.FromMilliseconds(200);
        options.MaxRetryDelay = TimeSpan.FromMilliseconds(400);
    };

    private static async Task<HealthReportEntry> ReadHealthAsync(TestApplication app)
    {
        HealthReport report = await app.Services
            .GetRequiredService<HealthCheckService>()
            .CheckHealthAsync();

        return report.Entries["autohttps"];
    }

    private static async Task WaitForEventAsync(TestApplication app, int eventId, TimeSpan timeout)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (app.Log.CountOf(eventId) > 0)
            {
                return;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException(
            $"Event {eventId} was not logged within {timeout}.{Environment.NewLine}{app.Log.Describe()}");
    }
}
