namespace AutoHttps.Diagnostics;

/// <summary>
/// The per-profile limits Let's Encrypt documents. An authority that reuses these profile names with
/// different limits is not second-guessed: an unrecognised profile returns null and the check that
/// depends on it is skipped rather than guessed at.
/// </summary>
internal static class ProfileLimits
{
    /// <summary>
    /// How many identifiers one certificate may carry under a profile, or null when the profile is not
    /// one whose limit is known.
    /// </summary>
    public static int? MaxIdentifiers(string? profile) => profile switch
    {
        CertificateProfiles.Classic => 100,
        CertificateProfiles.TlsServer => 25,
        CertificateProfiles.ShortLived => 25,
        _ => null,
    };

    /// <summary>
    /// Whether a profile can carry IP address identifiers. Only the short-lived profile does, and the
    /// default when no profile is requested is <c>classic</c>, which cannot.
    /// </summary>
    public static bool AllowsIpIdentifiers(string? profile) =>
        string.Equals(profile, CertificateProfiles.ShortLived, System.StringComparison.Ordinal);
}
