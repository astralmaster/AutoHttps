using System;

namespace AutoHttps.Renewal;

internal static class RenewalSchedule
{
    /// <summary>
    /// How long to wait before checking a certificate again. The base is the sooner of the renewal
    /// time and the configured check interval. When the authority's renewal-information response asked
    /// to be queried again by a certain time (RFC 9773 section 4.2), the wait is shortened to meet it,
    /// but never below <paramref name="minRecheck"/> and never past the renewal time, so a small or
    /// stale Retry-After cannot turn the loop into a tight poll or delay a renewal that is already due.
    /// </summary>
    public static TimeSpan ComputeCheckDelay(
        DateTimeOffset now,
        DateTimeOffset renewAt,
        DateTimeOffset? recheckAt,
        TimeSpan checkInterval,
        TimeSpan minRecheck)
    {
        TimeSpan wait = renewAt - now;
        if (wait > checkInterval)
        {
            wait = checkInterval;
        }

        if (recheckAt is { } at && at > now)
        {
            TimeSpan untilRecheck = at - now;
            if (untilRecheck < minRecheck)
            {
                untilRecheck = minRecheck;
            }

            if (untilRecheck < wait)
            {
                wait = untilRecheck;
            }
        }

        return wait;
    }
}
