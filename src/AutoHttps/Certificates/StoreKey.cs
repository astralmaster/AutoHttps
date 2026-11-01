using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AutoHttps.Certificates;

internal static class StoreKey
{
    private const int MaxPrefixLength = 48;
    private const int HashLength = 12;

    /// <summary>
    /// Names the stored certificate after both the domains and the authority that issued it.
    /// Leaving the authority out would let an application that moved from a staging endpoint to a
    /// production one pick the staging certificate back up and serve it as though it were trusted.
    /// </summary>
    public static string ForCertificate(Uri directoryUri, IReadOnlyList<string> identifiers)
    {
        string[] sorted = identifiers.OrderBy(static value => value, StringComparer.OrdinalIgnoreCase).ToArray();
        return Sanitize(sorted[0]) + "-" + Hash(directoryUri.AbsoluteUri + "|" + string.Join(',', sorted));
    }

    public static string ForAccount(Uri directoryUri, string contact) =>
        "account-" + Hash(directoryUri.AbsoluteUri + "|" + contact);

    /// <summary>
    /// Names the copy of the most recent certificate kept for each authority and application. A
    /// certificate is otherwise filed under its exact name set, so changing the configured names leaves
    /// nothing to serve, not even for the names that stayed, until a certificate for the new set is
    /// issued. The application is part of the name because every application of the same user shares
    /// the default storage directory, and one copy for all of them would hold whichever wrote last.
    /// </summary>
    public static string ForLatest(Uri directoryUri, string applicationName) =>
        "latest-" + Hash(directoryUri.AbsoluteUri + "|" + applicationName);

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..HashLength].ToLowerInvariant();

    private static string Sanitize(string identifier)
    {
        var builder = new StringBuilder(identifier.Length);

        foreach (char c in identifier)
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '.' or '-')
            {
                builder.Append(char.ToLowerInvariant(c));
            }
            else if (c == '*')
            {
                builder.Append("wildcard");
            }
            else
            {
                builder.Append('_');
            }

            if (builder.Length >= MaxPrefixLength)
            {
                break;
            }
        }

        return builder.Length == 0 ? "certificate" : builder.ToString();
    }
}
