using System;

namespace AutoHttps.Renewal;

internal static class RetryBackoff
{
    /// <summary>
    /// Spreads a retry delay so a fleet of instances that failed at the same moment does not retry in
    /// lockstep and synchronize into the authority's rate limit. This is the "pick a random point in an
    /// interval" that Let's Encrypt's integration guide asks for. Equal jitter keeps at least half of
    /// the nominal backoff, then spreads the rest across the other half, so the delay is always in
    /// <c>[nominal / 2, nominal]</c> and the exponential schedule is preserved.
    /// </summary>
    /// <param name="nominal">The backoff the schedule arrived at.</param>
    /// <param name="random">A value in <c>[0, 1)</c>, for example from <see cref="Random.NextDouble"/>.</param>
    public static TimeSpan Jitter(TimeSpan nominal, double random)
    {
        if (nominal <= TimeSpan.Zero)
        {
            return TimeSpan.Zero;
        }

        double half = nominal.Ticks / 2d;
        long ticks = (long)(half + (half * Clamp01(random)));
        return TimeSpan.FromTicks(ticks);
    }

    private static double Clamp01(double value)
    {
        if (value < 0)
        {
            return 0;
        }

        return value > 1 ? 1 : value;
    }
}
