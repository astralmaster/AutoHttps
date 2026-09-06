using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AutoHttps.Internal;

/// <summary>
/// Finds the ASP.NET Core HTTPS development certificate that <c>dotnet dev-certs https</c> creates,
/// so a development build can serve a certificate the browser already trusts on localhost.
/// </summary>
internal static class DevelopmentCertificateLocator
{
    // The extension OID dotnet dev-certs stamps on the certificate it creates. Matching on it is how
    // the certificate is told apart from anything else in the personal store.
    private const string AspNetHttpsOid = "1.3.6.1.4.1.311.84.1.1";

    public static X509Certificate2? Find(DateTimeOffset now)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

        try
        {
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        }
        catch (CryptographicException)
        {
            // No personal store on this machine, which is the normal case in a bare container.
            return null;
        }

        X509Certificate2Collection candidates = store.Certificates;
        X509Certificate2? chosen = Select(candidates, now);

        // The certificates handed back by the store are independent objects the caller owns. The one
        // being returned outlives the store; the rest are disposed here so they do not leak.
        foreach (X509Certificate2 candidate in candidates)
        {
            if (!ReferenceEquals(candidate, chosen))
            {
                candidate.Dispose();
            }
        }

        return chosen;
    }

    /// <summary>
    /// Picks the newest usable development certificate from a set. Separated from the store lookup so
    /// the selection can be tested without a certificate installed on the machine.
    /// </summary>
    public static X509Certificate2? Select(X509Certificate2Collection candidates, DateTimeOffset now)
    {
        X509Certificate2? best = null;

        foreach (X509Certificate2 candidate in candidates)
        {
            if (!IsDevelopmentCertificate(candidate) || !candidate.HasPrivateKey)
            {
                continue;
            }

            if (candidate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
            {
                continue;
            }

            if (best is null || candidate.NotAfter > best.NotAfter)
            {
                best = candidate;
            }
        }

        return best;
    }

    private static bool IsDevelopmentCertificate(X509Certificate2 certificate)
    {
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (string.Equals(extension.Oid?.Value, AspNetHttpsOid, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
