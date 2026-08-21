using System;
using System.Collections.Generic;
using AutoHttps.Challenges;

namespace AutoHttps;

/// <summary>
/// Configures how AutoHttps obtains and renews certificates.
/// </summary>
public sealed class AutoHttpsOptions
{
    /// <summary>
    /// The domains to request a certificate for. A wildcard such as <c>*.example.com</c> requires
    /// a <see cref="DnsChallengeProvider"/>, because no other challenge type can validate one.
    /// </summary>
    public IList<string> DomainNames { get; } = [];

    /// <summary>
    /// The contact address registered with the certificate authority. Used for account recovery and,
    /// at some authorities, for problem notifications.
    /// </summary>
    public string? EmailAddress { get; set; }

    /// <summary>
    /// Set to <see langword="true"/> to accept the certificate authority's subscriber agreement.
    /// Startup fails while this is <see langword="false"/>; the agreement URL is included in the error.
    /// </summary>
    public bool AcceptTermsOfService { get; set; }

    /// <summary>
    /// The ACME directory to use. Defaults to <see cref="CertificateAuthorities.LetsEncrypt"/>.
    /// Point this at <see cref="CertificateAuthorities.LetsEncryptStaging"/> while developing.
    /// </summary>
    public Uri CertificateAuthority { get; set; } = CertificateAuthorities.LetsEncrypt;

    /// <summary>
    /// The certificate profile to request, for example <see cref="CertificateProfiles.ShortLived"/>.
    /// Leave <see langword="null"/> to accept the authority's default. Ignored by authorities that
    /// do not advertise profiles.
    /// </summary>
    public string? Profile { get; set; }

    /// <summary>The key algorithm for issued certificates. Defaults to <see cref="KeyAlgorithm.EcdsaP256"/>.</summary>
    public KeyAlgorithm KeyAlgorithm { get; set; } = KeyAlgorithm.EcdsaP256;

    /// <summary>
    /// Where certificates and the account key are written. Defaults to <c>autohttps</c> under the
    /// user's local application data directory. In a container, point this at a mounted volume;
    /// otherwise every restart requests a new certificate and will exhaust the authority's rate limits.
    /// </summary>
    public string? StorageDirectory { get; set; }

    /// <summary>
    /// Credentials binding the ACME account to an existing account at the authority.
    /// Required by ZeroSSL, Google Trust Services and Sectigo.
    /// </summary>
    public ExternalAccountBinding? ExternalAccountBinding { get; set; }

    /// <summary>
    /// Publishes DNS TXT records for <c>dns-01</c> challenges. Required for wildcard certificates.
    /// </summary>
    public IDnsChallengeProvider? DnsChallengeProvider { get; set; }

    /// <summary>
    /// The challenge type to use when the authority offers a choice. Defaults to <c>http-01</c>.
    /// Set to <c>dns-01</c> when inbound port 80 is not reachable.
    /// </summary>
    public string PreferredChallengeType { get; set; } = ChallengeTypes.Http01;

    /// <summary>
    /// How long to wait after publishing a DNS record before asking the authority to validate it.
    /// Defaults to 30 seconds.
    /// </summary>
    public TimeSpan DnsPropagationDelay { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How often to re-evaluate whether a certificate needs renewing. Defaults to 6 hours, which
    /// satisfies the once-a-day renewal information polling that RFC 9773 asks for and is frequent
    /// enough for six day certificates.
    /// </summary>
    public TimeSpan RenewalCheckInterval { get; set; } = TimeSpan.FromHours(6);

    /// <summary>
    /// The fraction of a certificate's lifetime that must remain before it is renewed, used when the
    /// authority does not supply renewal information. Defaults to one third, which renews a 90 day
    /// certificate after 60 days and a six day certificate after roughly four.
    /// </summary>
    public double RenewalThreshold { get; set; } = 1d / 3d;

    /// <summary>
    /// Whether to ask the authority when to renew, using ACME Renewal Information (RFC 9773).
    /// Defaults to <see langword="true"/>. When the authority supplies a window it overrides
    /// <see cref="RenewalThreshold"/>.
    /// </summary>
    public bool UseRenewalInformation { get; set; } = true;

    /// <summary>How long to wait for the authority to validate a challenge. Defaults to 5 minutes.</summary>
    public TimeSpan ValidationTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How often to poll the authority while waiting. Defaults to 2 seconds.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>How long to wait before retrying after a failed order. Defaults to 1 minute, doubling up to <see cref="MaxRetryDelay"/>.</summary>
    public TimeSpan InitialRetryDelay { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>The ceiling for the retry backoff after repeated failures. Defaults to 6 hours.</summary>
    public TimeSpan MaxRetryDelay { get; set; } = TimeSpan.FromHours(6);

    /// <summary>
    /// Whether to attach the certificate selector to Kestrel's HTTPS defaults. Defaults to
    /// <see langword="true"/>. Set to <see langword="false"/> to wire endpoints yourself with
    /// <see cref="ListenOptionsExtensions.UseAutoHttps(Microsoft.AspNetCore.Server.Kestrel.Core.ListenOptions, IServiceProvider)"/>.
    /// </summary>
    public bool ConfigureKestrel { get; set; } = true;

    /// <summary>
    /// Whether to serve a self-signed certificate for configured domains until a real one is issued,
    /// so that TLS connections fail with a certificate warning rather than a handshake error.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool ServeFallbackCertificate { get; set; } = true;

    /// <summary>
    /// Whether to answer <c>http-01</c> challenges from the application's own request pipeline.
    /// Defaults to <see langword="true"/>. Set to <see langword="false"/> if another component
    /// already serves <c>/.well-known/acme-challenge</c>.
    /// </summary>
    public bool HandleHttp01Requests { get; set; } = true;
}
