using System;

namespace AutoHttps.Renewal;

/// <summary>
/// Turns the lifetime of the certificate in hand into the thresholds that depend on it. A fixed
/// number of days cannot serve both a 90 day certificate and a 160 hour one, so every threshold here
/// is a share of the lifetime rather than an absolute span.
/// </summary>
internal static class RenewalRisk
{
    /// <summary>
    /// The share of a certificate's lifetime that caps the retry backoff. Certify The Web caps its
    /// own at "48 hours or 10% of the certificate lifetime, whichever is shorter"; the proportional
    /// half is what keeps a short-lived certificate getting several attempts before it expires, which
    /// a flat ceiling cannot do.
    /// </summary>
    public const double RetryCeilingFraction = 0.1;

    /// <summary>
    /// The near-expiry fraction in effect: the configured one, or half the renewal threshold when it
    /// was left alone. Deriving the default keeps it below the point where renewal starts whatever
    /// the threshold is set to, so the two options cannot be configured into contradicting each other.
    /// </summary>
    public static double EffectiveNearExpiryFraction(double? configured, double renewalThreshold) =>
        configured ?? renewalThreshold / 2;

    /// <summary>
    /// How long before expiry a certificate counts as near expiry, as a share of its lifetime. Zero
    /// or less turns it off.
    /// </summary>
    public static TimeSpan NearExpiry(DateTimeOffset notBefore, DateTimeOffset notAfter, double fraction)
    {
        if (fraction <= 0 || notAfter <= notBefore || double.IsNaN(fraction))
        {
            return TimeSpan.Zero;
        }

        TimeSpan lifetime = notAfter - notBefore;
        return fraction >= 1 ? lifetime : lifetime * fraction;
    }

    /// <summary>
    /// The ceiling for the retry backoff while a certificate is in hand: the configured ceiling, or a
    /// tenth of this certificate's lifetime when that is shorter. Without the proportional cap, a
    /// ceiling set for a 90 day certificate leaves a 160 hour one only a couple of attempts between
    /// the renewal point and expiry.
    /// </summary>
    public static TimeSpan RetryCeiling(TimeSpan configured, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        if (notAfter <= notBefore)
        {
            return configured;
        }

        TimeSpan relative = (notAfter - notBefore) * RetryCeilingFraction;
        return relative > TimeSpan.Zero && relative < configured ? relative : configured;
    }

    /// <summary>
    /// Whether renewal has gone past being a failed attempt and into not being replaced in time:
    /// orders are failing and the certificate has entered the near-expiry window, so the runway the
    /// renewal threshold left has been spent. A failure with the whole runway still ahead is not
    /// overdue, which is what separates a blip from an outage worth waking someone for.
    /// </summary>
    public static bool IsOverdue(
        DateTimeOffset now,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        double nearExpiryFraction,
        int consecutiveFailures)
    {
        if (consecutiveFailures <= 0)
        {
            return false;
        }

        TimeSpan nearExpiry = NearExpiry(notBefore, notAfter, nearExpiryFraction);
        return nearExpiry > TimeSpan.Zero && notAfter - now <= nearExpiry;
    }
}
