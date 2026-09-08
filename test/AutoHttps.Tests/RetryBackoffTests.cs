using System;
using AutoHttps.Renewal;
using Xunit;

namespace AutoHttps.Tests;

public sealed class RetryBackoffTests
{
    private static readonly TimeSpan Nominal = TimeSpan.FromSeconds(100);

    [Fact]
    public void AtTheLowEndItKeepsHalfOfTheBackoff() =>
        Assert.Equal(TimeSpan.FromSeconds(50), RetryBackoff.Jitter(Nominal, 0));

    [Fact]
    public void AtTheHighEndItKeepsTheWholeBackoff() =>
        Assert.Equal(Nominal, RetryBackoff.Jitter(Nominal, 1));

    [Theory]
    [InlineData(0.0)]
    [InlineData(0.25)]
    [InlineData(0.5)]
    [InlineData(0.75)]
    [InlineData(0.999)]
    public void ItAlwaysStaysBetweenHalfAndTheWholeBackoff(double random)
    {
        TimeSpan jittered = RetryBackoff.Jitter(Nominal, random);

        Assert.InRange(jittered, TimeSpan.FromSeconds(50), Nominal);
    }

    [Theory]
    [InlineData(-1.0)]
    [InlineData(2.0)]
    public void ItClampsRandomnessOutsideTheUnitInterval(double random)
    {
        TimeSpan jittered = RetryBackoff.Jitter(Nominal, random);

        Assert.InRange(jittered, TimeSpan.FromSeconds(50), Nominal);
    }

    [Fact]
    public void DifferentRandomnessDecorrelatesTheDelay()
    {
        // Two instances that failed together must not land on the same retry moment.
        Assert.NotEqual(RetryBackoff.Jitter(Nominal, 0.2), RetryBackoff.Jitter(Nominal, 0.8));
    }

    [Fact]
    public void AZeroBackoffStaysZero() =>
        Assert.Equal(TimeSpan.Zero, RetryBackoff.Jitter(TimeSpan.Zero, 0.5));
}
