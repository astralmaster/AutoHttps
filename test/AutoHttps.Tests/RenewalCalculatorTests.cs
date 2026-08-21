using System;
using AutoHttps.Renewal;
using Xunit;

namespace AutoHttps.Tests;

public class RenewalCalculatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Serial = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    private const double OneThird = 1d / 3d;

    [Fact]
    public void WithoutRenewalInformation_A90DayCertificateIsRenewedAfter60Days()
    {
        DateTimeOffset notBefore = Now;
        DateTimeOffset notAfter = Now.AddDays(90);

        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            notBefore, notAfter, suggestedWindow: null, Serial, OneThird, Now);

        Assert.Equal(Now.AddDays(60), renewAt);
    }

    [Fact]
    public void WithoutRenewalInformation_ASixDayCertificateIsRenewedWithTwoDaysLeft()
    {
        // Let's Encrypt issues "shortlived" certificates for 160 hours and asks clients to renew
        // every two to three days. The same one third rule has to produce that without special casing.
        DateTimeOffset notBefore = Now;
        DateTimeOffset notAfter = Now.AddHours(160);

        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            notBefore, notAfter, suggestedWindow: null, Serial, OneThird, Now);

        TimeSpan remaining = notAfter - renewAt;
        Assert.InRange(remaining.TotalHours, 52, 54);
    }

    [Fact]
    public void AnExpiredCertificateIsRenewedImmediately()
    {
        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            Now.AddDays(-90), Now.AddDays(-1), suggestedWindow: null, Serial, OneThird, Now);

        Assert.Equal(Now, renewAt);
    }

    [Fact]
    public void ACertificateWithAnInvertedValidityIsRenewedImmediately()
    {
        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            Now.AddDays(10), Now.AddDays(5), suggestedWindow: null, Serial, OneThird, Now);

        Assert.Equal(Now, renewAt);
    }

    [Fact]
    public void ASuggestedWindowOverridesTheThreshold()
    {
        var window = new RenewalWindow(Now.AddDays(1), Now.AddDays(2));

        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            Now, Now.AddDays(90), window, Serial, OneThird, Now);

        Assert.InRange(renewAt, window.Start, window.End);
    }

    [Fact]
    public void ASuggestedWindowInThePastRenewsImmediately()
    {
        var window = new RenewalWindow(Now.AddDays(-2), Now.AddDays(-1));

        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            Now, Now.AddDays(90), window, Serial, OneThird, Now);

        Assert.Equal(Now, renewAt);
    }

    [Fact]
    public void AZeroWidthWindowFallsBackToTheThreshold()
    {
        var window = new RenewalWindow(Now.AddDays(1), Now.AddDays(1));

        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            Now, Now.AddDays(90), window, Serial, OneThird, Now);

        Assert.Equal(Now.AddDays(60), renewAt);
    }

    [Fact]
    public void TheChoiceWithinAWindowIsStableForTheSameCertificate()
    {
        var window = new RenewalWindow(Now.AddDays(1), Now.AddDays(2));

        DateTimeOffset first = RenewalCalculator.ComputeRenewalTime(Now, Now.AddDays(90), window, Serial, OneThird, Now);
        DateTimeOffset second = RenewalCalculator.ComputeRenewalTime(Now, Now.AddDays(90), window, Serial, OneThird, Now.AddMinutes(5));

        Assert.Equal(first, second);
    }

    [Fact]
    public void DifferentCertificatesSpreadAcrossTheWindow()
    {
        var window = new RenewalWindow(Now.AddDays(1), Now.AddDays(2));
        var picks = new System.Collections.Generic.HashSet<DateTimeOffset>();

        for (int i = 0; i < 64; i++)
        {
            byte[] serial = [(byte)i, 0x11, 0x22, 0x33];
            picks.Add(RenewalCalculator.ComputeRenewalTime(Now, Now.AddDays(90), window, serial, OneThird, Now));
        }

        // A client that renewed at a fixed point in the window would hammer the authority at once.
        Assert.True(picks.Count > 50, $"Expected the renewal times to spread out, but only {picks.Count} of 64 were distinct.");
    }

    [Fact]
    public void RenewalNeverLandsAfterExpiry()
    {
        var window = new RenewalWindow(Now.AddDays(80), Now.AddDays(200));

        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            Now, Now.AddDays(90), window, Serial, OneThird, Now);

        Assert.True(renewAt <= Now.AddDays(90));
    }

    [Theory]
    [InlineData(0.1)]
    [InlineData(0.5)]
    [InlineData(0.9)]
    public void TheThresholdIsTheFractionOfLifetimeLeftAtRenewal(double threshold)
    {
        DateTimeOffset notBefore = Now;
        DateTimeOffset notAfter = Now.AddDays(100);

        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            notBefore, notAfter, suggestedWindow: null, Serial, threshold, Now);

        Assert.Equal(notAfter - TimeSpan.FromDays(100 * threshold), renewAt);
    }
}
