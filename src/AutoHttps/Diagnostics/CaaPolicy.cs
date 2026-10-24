using System;
using System.Collections.Generic;
using System.Globalization;

namespace AutoHttps.Diagnostics;

/// <summary>What a domain's CAA records say about one certificate authority.</summary>
internal enum CaaVerdict
{
    /// <summary>Nothing restricts issuance: either no CAA records, or none carrying an issue tag.</summary>
    NoPolicy,

    /// <summary>The records name this authority, with no parameter that rules this order out.</summary>
    Permitted,

    /// <summary>The records restrict issuance and do not name this authority.</summary>
    Forbidden,

    /// <summary>The records name this authority, but only for validation methods other than the one in use.</summary>
    ForbiddenMethod,

    /// <summary>The records name this authority, but only for a different ACME account.</summary>
    ForbiddenAccount,

    /// <summary>The records name this authority for one ACME account, and this application's is not known yet.</summary>
    UnverifiedAccount,

    /// <summary>A property this check does not understand is marked critical, which tells an authority to refuse.</summary>
    UnknownCritical,
}

/// <summary>
/// Reads CAA records and decides whether they permit an authority to issue (RFC 8659), including the
/// accounturi and validationmethods parameters of RFC 8657, which Let's Encrypt enforces and every
/// publicly trusted authority must from 2027-03-15 (CA/Browser Forum ballot SC-098v2). This only
/// reports; the authority does the authoritative check, and a client cannot see the same view of DNS
/// that the authority's several validation perspectives do.
/// </summary>
internal static class CaaPolicy
{
    private const string Issue = "issue";
    private const string IssueWild = "issuewild";
    private const int CriticalFlag = 128;

    // The tags in common use. An authority refuses on any other tag that is marked critical.
    private static readonly HashSet<string> KnownTags = new(StringComparer.OrdinalIgnoreCase)
    {
        Issue, IssueWild, "iodef", "issuemail", "issuevmc", "contactemail", "contactphone",
    };

    /// <summary>
    /// Evaluates a record set that was found at one name.
    /// </summary>
    /// <param name="records">The CAA record data, as a resolver returns it, for example <c>0 issue "letsencrypt.org"</c>.</param>
    /// <param name="authorityIdentities">The identities the authority publishes in its directory metadata.</param>
    /// <param name="wildcard">Whether the certificate covers a wildcard name, which gives issuewild precedence.</param>
    /// <param name="challengeType">The ACME challenge that will validate the name, for example <c>http-01</c>.</param>
    /// <param name="accountUri">This application's ACME account URL, or null when it is not known yet.</param>
    /// <returns>The verdict.</returns>
    public static CaaVerdict Evaluate(
        IReadOnlyList<string> records,
        IReadOnlyList<string> authorityIdentities,
        bool wildcard,
        string challengeType = Challenges.ChallengeTypes.Http01,
        string? accountUri = null)
    {
        var issue = new List<string>();
        var issueWild = new List<string>();

        foreach (string record in records)
        {
            if (!TryParse(record, out int flags, out string tag, out string value))
            {
                continue;
            }

            // RFC 8659 section 4.1: an authority must not issue when a property it does not understand is
            // marked critical, whatever the rest of the set says.
            if ((flags & CriticalFlag) != 0 && !KnownTags.Contains(tag))
            {
                return CaaVerdict.UnknownCritical;
            }

            if (string.Equals(tag, Issue, StringComparison.OrdinalIgnoreCase))
            {
                issue.Add(value);
            }
            else if (string.Equals(tag, IssueWild, StringComparison.OrdinalIgnoreCase))
            {
                issueWild.Add(value);
            }
        }

        // RFC 8659 section 4.3: issuewild, when present, replaces issue for a wildcard rather than
        // adding to it. For a name that is not a wildcard, issuewild is not consulted at all.
        List<string> relevant = wildcard && issueWild.Count > 0 ? issueWild : issue;

        // RFC 8659 section 4.2: a record set carrying no relevant issue tag does not restrict issuance.
        if (relevant.Count == 0)
        {
            return CaaVerdict.NoPolicy;
        }

        // Any one record that permits this order is enough, so a refusal is only the answer once every
        // record naming the authority has been tried.
        CaaVerdict refusal = CaaVerdict.Forbidden;

        foreach (string candidate in relevant)
        {
            if (!TrySplit(candidate, out string domain, out Dictionary<string, string> parameters) ||
                !Names(domain, authorityIdentities))
            {
                continue;
            }

            if (parameters.TryGetValue("validationmethods", out string? methods) &&
                !ListContains(methods, challengeType))
            {
                refusal = Prefer(refusal, CaaVerdict.ForbiddenMethod);
                continue;
            }

            if (parameters.TryGetValue("accounturi", out string? pinned))
            {
                if (accountUri is null)
                {
                    refusal = Prefer(refusal, CaaVerdict.UnverifiedAccount);
                    continue;
                }

                if (!string.Equals(pinned, accountUri, StringComparison.Ordinal))
                {
                    refusal = Prefer(refusal, CaaVerdict.ForbiddenAccount);
                    continue;
                }
            }

            return CaaVerdict.Permitted;
        }

        return refusal;
    }

    /// <summary>Splits one record into its tag and value.</summary>
    internal static bool TryParse(string record, out string tag, out string value) =>
        TryParse(record, out _, out tag, out value);

    private static bool TryParse(string record, out int flags, out string tag, out string value)
    {
        flags = 0;
        tag = string.Empty;
        value = string.Empty;

        if (string.IsNullOrWhiteSpace(record))
        {
            return false;
        }

        string[] parts = record.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 3)
        {
            return false;
        }

        _ = int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out flags);
        tag = parts[1];
        value = parts[2].Trim().Trim('"').Trim();

        return true;
    }

    /// <summary>
    /// Splits an issue value into the authority's domain and its parameters (RFC 8659 section 4.2). An
    /// empty domain is the ";" that forbids everyone, which names no authority.
    /// </summary>
    private static bool TrySplit(string value, out string domain, out Dictionary<string, string> parameters)
    {
        parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string[] parts = value.Split(';', StringSplitOptions.TrimEntries);

        domain = parts[0];

        for (int i = 1; i < parts.Length; i++)
        {
            int equals = parts[i].IndexOf('=', StringComparison.Ordinal);
            if (equals > 0)
            {
                parameters[parts[i][..equals].Trim()] = parts[i][(equals + 1)..].Trim();
            }
        }

        return domain.Length > 0;
    }

    private static bool Names(string domain, IReadOnlyList<string> authorityIdentities)
    {
        foreach (string identity in authorityIdentities)
        {
            if (string.Equals(domain, identity, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ListContains(string list, string item)
    {
        foreach (string entry in list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (string.Equals(entry, item, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    // A record that names the authority says more about why issuance would fail than one that does not,
    // so the reason it gives is kept over the plain refusal. One pinned to an account that cannot be
    // checked yet may still permit this order, so that outweighs a definite refusal by another record.
    private static CaaVerdict Prefer(CaaVerdict current, CaaVerdict candidate) =>
        current == CaaVerdict.Forbidden || candidate == CaaVerdict.UnverifiedAccount ? candidate : current;
}
