using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AutoHttps.Certificates;

/// <summary>
/// Picks between the certificate chains an authority offers. A chain is identified by the issuer of
/// its topmost certificate, which is the trust anchor a client has to already hold, and that is what
/// <c>PreferredChain</c> names. This matches certbot's <c>--preferred-chain</c>.
/// </summary>
internal static class ChainSelector
{
    /// <summary>
    /// Whether the given chain leads up to a root whose common name matches <paramref name="preferredIssuer"/>.
    /// </summary>
    public static bool Matches(string chainPem, string preferredIssuer) =>
        string.Equals(TopIssuer(chainPem), preferredIssuer.Trim(), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The common name of the issuer of the chain's topmost certificate, or a placeholder when the
    /// chain cannot be read. Used both to match a preference and to name what was offered in a log.
    /// </summary>
    public static string TopIssuer(string chainPem)
    {
        var chain = new X509Certificate2Collection();
        try
        {
            chain.ImportFromPem(chainPem);
            if (chain.Count == 0)
            {
                return "unknown";
            }

            // A chain is the leaf first, then each certificate that signed the one before it, so the
            // last entry is closest to the root and its issuer is the anchor an operator pins.
            string issuer = chain[^1].GetNameInfo(X509NameType.SimpleName, forIssuer: true);
            return string.IsNullOrEmpty(issuer) ? "unknown" : issuer;
        }
        catch (CryptographicException)
        {
            return "unknown";
        }
        finally
        {
            foreach (X509Certificate2 certificate in chain)
            {
                certificate.Dispose();
            }
        }
    }
}
