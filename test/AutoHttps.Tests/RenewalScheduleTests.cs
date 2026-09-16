using System;
using AutoHttps.Renewal;
using Xunit;

namespace AutoHttps.Tests;

public sealed class RenewalScheduleTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan MinRecheck = TimeSpan.FromSeconds(30);

    [Fact]
    public void WithoutARecheckTheWaitIsTheSoonerOfRenewalAndTheCheckInterval()
    {
        DateTimeOffset renewAt = Now.AddHours(2);

        TimeSpan wait = RenewalSchedule.ComputeCheckDelay(Now, renewAt, recheckAt: null, CheckInterval, MinRecheck);

        Assert.Equal(TimeSpan.FromHours(2), wait);
    }

    [Fact]
    public void ADistantRenewalIsCappedAtTheCheckInterval()
    {
        DateTimeOffset renewAt = Now.AddDays(30);

        TimeSpan wait = RenewalSchedule.ComputeCheckDelay(Now, renewAt, recheckAt: null, CheckInterval, MinRecheck);

        Assert.Equal(CheckInterval, wait);
    }

    [Fact]
    public void ASoonerRecheckShortensTheWait()
    {
        DateTimeOffset renewAt = Now.AddDays(30);
        DateTimeOffset recheckAt = Now.AddHours(1);

        TimeSpan wait = RenewalSchedule.ComputeCheckDelay(Now, renewAt, recheckAt, CheckInterval, MinRecheck);

        Assert.Equal(TimeSpan.FromHours(1), wait);
    }

    [Fact]
    public void ARecheckLaterThanTheCheckIntervalDoesNotExtendTheWait()
    {
        DateTimeOffset renewAt = Now.AddDays(30);
        DateTimeOffset recheckAt = Now.AddHours(12);

        TimeSpan wait = RenewalSchedule.ComputeCheckDelay(Now, renewAt, recheckAt, CheckInterval, MinRecheck);

        Assert.Equal(CheckInterval, wait);
    }

    [Fact]
    public void AnImminentRenewalIsNotDelayedByAFlooredRecheck()
    {
        // The renewal is closer than the floor, so the floor must not push the wait out past it.
        DateTimeOffset renewAt = Now.AddSeconds(5);
        DateTimeOffset recheckAt = Now.AddSeconds(1);

        TimeSpan wait = RenewalSchedule.ComputeCheckDelay(Now, renewAt, recheckAt, CheckInterval, MinRecheck);

        Assert.Equal(TimeSpan.FromSeconds(5), wait);
    }

    [Fact]
    public void ATinyRecheckIsHeldToTheFloor()
    {
        DateTimeOffset renewAt = Now.AddDays(30);
        DateTimeOffset recheckAt = Now.AddSeconds(1);

        TimeSpan wait = RenewalSchedule.ComputeCheckDelay(Now, renewAt, recheckAt, CheckInterval, MinRecheck);

        Assert.Equal(MinRecheck, wait);
    }

    [Fact]
    public void ARecheckInThePastIsIgnored()
    {
        DateTimeOffset renewAt = Now.AddHours(2);
        DateTimeOffset recheckAt = Now.AddMinutes(-5);

        TimeSpan wait = RenewalSchedule.ComputeCheckDelay(Now, renewAt, recheckAt, CheckInterval, MinRecheck);

        Assert.Equal(TimeSpan.FromHours(2), wait);
    }
}
