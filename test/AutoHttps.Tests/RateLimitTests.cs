using System;
using AutoHttps.Renewal;
using Xunit;

namespace AutoHttps.Tests;

public sealed class RateLimitTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan MaxWithoutCertificate = TimeSpan.FromHours(1);

    [Theory]
    [InlineData(5)]     // minutes
    [InlineData(60)]    // an hour
    [InlineData(360)]   // six hours
    public void AnOrdinaryPauseIsHonouredExactlyWhileACertificateHasPlentyOfLifeLeft(int minutes)
    {
        DateTimeOffset expiry = Now.AddDays(30);
        DateTimeOffset retryAfter = Now.AddMinutes(minutes);

        DateTimeOffset deadline = RateLimit.ClampDeadline(retryAfter, Now, expiry, MaxWithoutCertificate);

        Assert.Equal(retryAfter, deadline);
    }

    [Fact]
    public void AnAbsurdPauseIsCappedSoARetryLandsWhileTheCertificateIsStillValid()
    {
        DateTimeOffset expiry = Now.AddDays(10);
        DateTimeOffset retryAfter = Now.AddDays(365);

        DateTimeOffset deadline = RateLimit.ClampDeadline(retryAfter, Now, expiry, MaxWithoutCertificate);

        // Half of the remaining ten days, and well before the certificate expires.
        Assert.Equal(Now.AddDays(5), deadline);
        Assert.True(deadline < expiry);
    }

    [Fact]
    public void TheCapShrinksWithTheRemainingValiditySoAShortLivedCertificateStillRenews()
    {
        // A six-day certificate a day from expiry cannot afford a long pause.
        DateTimeOffset expiry = Now.AddDays(1);
        DateTimeOffset retryAfter = Now.AddDays(7);

        DateTimeOffset deadline = RateLimit.ClampDeadline(retryAfter, Now, expiry, MaxWithoutCertificate);

        Assert.Equal(Now.AddHours(12), deadline);
    }

    [Fact]
    public void WithNoCertificateYetThePauseIsCappedAtTheStartupBound()
    {
        DateTimeOffset retryAfter = Now.AddDays(365);

        DateTimeOffset deadline = RateLimit.ClampDeadline(retryAfter, Now, currentExpiry: null, MaxWithoutCertificate);

        Assert.Equal(Now + MaxWithoutCertificate, deadline);
    }

    [Fact]
    public void WithNoCertificateYetAShortPauseIsStillHonoured()
    {
        DateTimeOffset retryAfter = Now.AddMinutes(10);

        DateTimeOffset deadline = RateLimit.ClampDeadline(retryAfter, Now, currentExpiry: null, MaxWithoutCertificate);

        Assert.Equal(retryAfter, deadline);
    }

    [Fact]
    public void AnAlreadyExpiredCertificateFallsBackToTheStartupBound()
    {
        DateTimeOffset expiry = Now.AddMinutes(-1);
        DateTimeOffset retryAfter = Now.AddDays(365);

        DateTimeOffset deadline = RateLimit.ClampDeadline(retryAfter, Now, expiry, MaxWithoutCertificate);

        Assert.Equal(Now + MaxWithoutCertificate, deadline);
    }
}
