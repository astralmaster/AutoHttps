using System;
using System.Collections.Generic;
using AutoHttps.Internal;

namespace AutoHttps.Challenges;

/// <summary>
/// The names involved in a <c>dns-01</c> challenge: the one the authority reads, and the one the record
/// is written at, which differ when <see cref="AutoHttpsOptions.DnsChallengeAliases"/> delegates it.
/// </summary>
internal static class DnsChallengeNames
{
    private const string Prefix = "_acme-challenge.";

    /// <summary>The name the authority reads for an identifier. A wildcard is validated at its apex.</summary>
    public static string ForIdentifier(string identifier) => Prefix + BaseName(identifier);

    /// <summary>The identifier without a wildcard label or a trailing dot, lowercased.</summary>
    public static string BaseName(string identifier) =>
        identifier.Trim().TrimEnd('.').TrimStart('*', '.').ToLowerInvariant();

    /// <summary>
    /// The aliases keyed by base name, with entries that are not usable left out. The options
    /// validator reports those, so here they only must not throw.
    /// </summary>
    public static IReadOnlyDictionary<string, string> Normalize(IEnumerable<KeyValuePair<string, string>> aliases)
    {
        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (KeyValuePair<string, string> alias in aliases)
        {
            if (DomainNormalizer.TryNormalize(alias.Key, out string key) &&
                DomainNormalizer.TryNormalizeRecordName(alias.Value, out string target))
            {
                normalized[BaseName(key)] = target;
            }
        }

        return normalized;
    }
}
