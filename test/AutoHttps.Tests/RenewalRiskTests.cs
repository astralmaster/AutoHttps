using System;
using AutoHttps.Renewal;
using Xunit;

namespace AutoHttps.Tests;

public sealed class RenewalRiskTests
{
    private static readonly DateTimeOffset Issued = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);

    // The two lifetimes the library has to serve at once: Let's Encrypt's classic certificate and its
    // short-lived profile. Every assertion below exists because one number cannot serve both.
    private static readonly TimeSpan Classic = TimeSpan.FromDays(90);
    private static readonly TimeSpan ShortLived = TimeSpan.FromHours(160);

    private const double DefaultFraction = 1d / 6d;

    [Fact]
    public void TheNearExpiryWindowScalesWithTheCertificateLifetime()
    {
        TimeSpan classic = RenewalRisk.NearExpiry(Issued, Issued + Classic, DefaultFraction);
        TimeSpan shortLived = RenewalRisk.NearExpiry(Issued, Issued + ShortLived, DefaultFraction);

        Assert.Equal(TimeSpan.FromDays(15), classic);
        Assert.Equal(TimeSpan.FromTicks(ShortLived.Ticks / 6), shortLived);
    }

    [Fact]
    public void TheDefaultFractionIsDerivedFromTheRenewalThreshold()
    {
        // Deriving it is what stops the two options contradicting each other. A fixed default would
        // sit above a lowered threshold and warn before renewal had been tried even once.
        Assert.Equal(1d / 6d, RenewalRisk.EffectiveNearExpiryFraction(null, 1d / 3d));
        Assert.Equal(0.05, RenewalRisk.EffectiveNearExpiryFraction(null, 0.1));

        // An explicit value is used as given, including zero, which turns the window off.
        Assert.Equal(0.25, RenewalRisk.EffectiveNearExpiryFraction(0.25, 1d / 3d));
        Assert.Equal(0, RenewalRisk.EffectiveNearExpiryFraction(0, 1d / 3d));
    }

    [Fact]
    public void AZeroFractionTurnsTheNearExpiryWindowOff()
    {
        Assert.Equal(TimeSpan.Zero, RenewalRisk.NearExpiry(Issued, Issued + Classic, 0));
        Assert.Equal(TimeSpan.Zero, RenewalRisk.NearExpiry(Issued, Issued + Classic, -1));
        Assert.Equal(TimeSpan.Zero, RenewalRisk.NearExpiry(Issued, Issued + Classic, double.NaN));
    }

    [Fact]
    public void ACertificateWithNoLifetimeHasNoNearExpiryWindow()
    {
        // Authorities differ on backdating and a host with an unsynced clock can see its own fresh
        // certificate as inverted. Dividing by that lifetime must not produce a threshold.
        Assert.Equal(TimeSpan.Zero, RenewalRisk.NearExpiry(Issued, Issued, DefaultFraction));
        Assert.Equal(TimeSpan.Zero, RenewalRisk.NearExpiry(Issued, Issued.AddDays(-1), DefaultFraction));
    }

    [Fact]
    public void AFractionOfOneOrMoreIsTheWholeLifetime()
    {
        Assert.Equal(Classic, RenewalRisk.NearExpiry(Issued, Issued + Classic, 1));
        Assert.Equal(Classic, RenewalRisk.NearExpiry(Issued, Issued + Classic, 4));
    }

    [Fact]
    public void TheConfiguredRetryCeilingIsKeptForALongLivedCertificate()
    {
        // A tenth of 90 days is nine days, far beyond the default ceiling, so nothing changes for the
        // lifetime almost everyone is on. This is what keeps the proportional cap from being a
        // silent behaviour change.
        TimeSpan ceiling = RenewalRisk.RetryCeiling(TimeSpan.FromHours(6), Issued, Issued + Classic);

        Assert.Equal(TimeSpan.FromHours(6), ceiling);
    }

    [Fact]
    public void AShortLivedCertificateHoldsTheCeilingToAShareOfItsLifetime()
    {
        // The case the flat ceiling cannot serve: 48 hours between attempts on a 160 hour
        // certificate leaves barely one attempt between the renewal point and expiry.
        TimeSpan ceiling = RenewalRisk.RetryCeiling(TimeSpan.FromHours(48), Issued, Issued + ShortLived);

        Assert.Equal(TimeSpan.FromHours(16), ceiling);
    }

    [Fact]
    public void TheCeilingLeavesEnoughAttemptsBeforeAShortLivedCertificateExpires()
    {
        // The property that matters, rather than the arithmetic: renewal starts a third of the way
        // out, so the ceiling has to fit several attempts into that runway.
        TimeSpan runway = ShortLived * (1d / 3d);
        TimeSpan ceiling = RenewalRisk.RetryCeiling(TimeSpan.FromHours(48), Issued, Issued + ShortLived);

        Assert.True(
            runway / ceiling >= 3,
            $"a {ceiling} ceiling only fits {runway / ceiling:F1} attempts into the {runway} runway");
    }

    [Fact]
    public void TheCeilingFallsBackToTheConfiguredValueWithoutALifetime()
    {
        TimeSpan configured = TimeSpan.FromHours(6);

        Assert.Equal(configured, RenewalRisk.RetryCeiling(configured, Issued, Issued));
        Assert.Equal(configured, RenewalRisk.RetryCeiling(configured, Issued, Issued.AddHours(-1)));
    }

    [Fact]
    public void OneFailureWithTheWholeRunwayAheadIsNotOverdue()
    {
        // The distinction the escalation exists for. A failed attempt 30 days before a 90 day
        // certificate expires is retried and almost always succeeds; paging on it is noise.
        DateTimeOffset now = Issued + Classic - TimeSpan.FromDays(30);

        Assert.False(IsOverdue(now, Classic, failures: 1));
    }

    [Fact]
    public void FailuresThatOutlastTheRunwayAreOverdue()
    {
        DateTimeOffset now = Issued + Classic - TimeSpan.FromDays(10);

        Assert.True(IsOverdue(now, Classic, failures: 1));
    }

    [Fact]
    public void TheOverdueBoundaryIsTheNearExpiryWindow()
    {
        DateTimeOffset justOutside = Issued + Classic - TimeSpan.FromDays(15) - TimeSpan.FromSeconds(1);
        DateTimeOffset onTheBoundary = Issued + Classic - TimeSpan.FromDays(15);

        Assert.False(IsOverdue(justOutside, Classic, failures: 4));
        Assert.True(IsOverdue(onTheBoundary, Classic, failures: 4));
    }

    [Fact]
    public void NothingIsOverdueWhileRenewalIsSucceeding()
    {
        // An expired certificate with no failing orders is a different fault, reported as unhealthy
        // rather than as overdue renewal, so the failure count has to be what gates this.
        DateTimeOffset now = Issued + Classic + TimeSpan.FromDays(1);

        Assert.False(IsOverdue(now, Classic, failures: 0));
    }

    [Fact]
    public void TurningTheNearExpiryWindowOffAlsoTurnsOverdueOff()
    {
        DateTimeOffset now = Issued + Classic - TimeSpan.FromMinutes(1);

        Assert.False(RenewalRisk.IsOverdue(now, Issued, Issued + Classic, 0, consecutiveFailures: 9));
    }

    [Fact]
    public void OverdueScalesWithLifetimeTheSameWayTheWindowDoes()
    {
        // One threshold, two correct answers from the same amount of time left. A hundred hours
        // remaining is four days of a 90 day certificate, which is overdue, and 62% of a 160 hour
        // certificate, which is not due at all. A fixed span would have to be wrong about one.
        TimeSpan remaining = TimeSpan.FromHours(100);

        Assert.True(IsOverdue(Issued + Classic - remaining, Classic, failures: 2));
        Assert.False(IsOverdue(Issued + ShortLived - remaining, ShortLived, failures: 2));
    }

    private static bool IsOverdue(DateTimeOffset now, TimeSpan lifetime, int failures) =>
        RenewalRisk.IsOverdue(now, Issued, Issued + lifetime, DefaultFraction, failures);
}
