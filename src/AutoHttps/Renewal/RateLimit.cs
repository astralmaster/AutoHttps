using System;

namespace AutoHttps.Renewal;

internal static class RateLimit
{
    /// <summary>
    /// Bounds how far a rate-limit pause may push the next attempt. The authority's <c>Retry-After</c>
    /// is honoured as given, unless it is so far out that renewal would be suspended until the
    /// certificate expired. Anything in front of the authority that emits the header, a CDN, an API
    /// gateway or a misconfigured proxy, can answer with an enormous value (a year, a date far in the
    /// future); left unbounded it parks renewal until the certificate lapses, with the process still
    /// running. The pause is capped at half the certificate's remaining validity, so a retry always
    /// lands while the certificate is still usable. With no certificate in hand there is nothing to
    /// lose and first issuance should keep trying, so the cap is <paramref name="maxWithoutCertificate"/>.
    /// </summary>
    /// <param name="retryAfter">The instant the authority asked to be left alone until.</param>
    /// <param name="now">The current time.</param>
    /// <param name="currentExpiry">When the certificate in hand expires, or null if there is none.</param>
    /// <param name="maxWithoutCertificate">The cap applied when no certificate exists yet.</param>
    public static DateTimeOffset ClampDeadline(
        DateTimeOffset retryAfter,
        DateTimeOffset now,
        DateTimeOffset? currentExpiry,
        TimeSpan maxWithoutCertificate)
    {
        TimeSpan cap = currentExpiry is { } expiry && expiry > now
            ? TimeSpan.FromTicks((expiry - now).Ticks / 2)
            : maxWithoutCertificate;

        DateTimeOffset ceiling = now + cap;
        return retryAfter < ceiling ? retryAfter : ceiling;
    }
}
