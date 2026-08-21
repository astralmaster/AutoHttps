using System;

namespace AutoHttps;

/// <summary>
/// Directory endpoints for well known ACME certificate authorities.
/// </summary>
public static class CertificateAuthorities
{
    /// <summary>Let's Encrypt production. Subject to strict rate limits; test against <see cref="LetsEncryptStaging"/> first.</summary>
    public static Uri LetsEncrypt { get; } = new("https://acme-v02.api.letsencrypt.org/directory");

    /// <summary>Let's Encrypt staging. Issues untrusted certificates and has generous rate limits.</summary>
    public static Uri LetsEncryptStaging { get; } = new("https://acme-staging-v02.api.letsencrypt.org/directory");

    /// <summary>ZeroSSL. Requires an <see cref="ExternalAccountBinding"/>.</summary>
    public static Uri ZeroSsl { get; } = new("https://acme.zerossl.com/v2/DV90");

    /// <summary>Google Trust Services. Requires an <see cref="ExternalAccountBinding"/>.</summary>
    public static Uri GoogleTrustServices { get; } = new("https://dv.acme-v02.api.pki.goog/directory");

    /// <summary>Buypass Go SSL production.</summary>
    public static Uri Buypass { get; } = new("https://api.buypass.com/acme/directory");

    /// <summary>Buypass Go SSL staging.</summary>
    public static Uri BuypassStaging { get; } = new("https://api.test4.buypass.no/acme/directory");
}

/// <summary>
/// Certificate profile names understood by Let's Encrypt. A profile selects the shape and
/// lifetime of the issued certificate and is sent with the order.
/// </summary>
public static class CertificateProfiles
{
    /// <summary>The historical profile, issuing certificates with a 90 day lifetime.</summary>
    public const string Classic = "classic";

    /// <summary>The current default profile, issuing certificates with a 45 day lifetime.</summary>
    public const string TlsServer = "tlsserver";

    /// <summary>
    /// Certificates valid for roughly six days. Requires a client that renews several times a week;
    /// AutoHttps handles this automatically.
    /// </summary>
    public const string ShortLived = "shortlived";
}
