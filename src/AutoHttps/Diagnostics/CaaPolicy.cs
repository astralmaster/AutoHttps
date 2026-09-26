using System;
using System.Collections.Generic;

namespace AutoHttps.Diagnostics;

/// <summary>What a domain's CAA records say about one certificate authority.</summary>
internal enum CaaVerdict
{
    /// <summary>Nothing restricts issuance: either no CAA records, or none carrying an issue tag.</summary>
    NoPolicy,

    /// <summary>The records name this authority.</summary>
    Permitted,

    /// <summary>The records restrict issuance and do not name this authority.</summary>
    Forbidden,
}

/// <summary>
/// Reads CAA records and decides whether they permit an authority to issue (RFC 8659). This only
/// reports; the authority does the authoritative check, and a client cannot see the same view of DNS
/// that the authority's several validation perspectives do.
/// </summary>
internal static class CaaPolicy
{
    private const string Issue = "issue";
    private const string IssueWild = "issuewild";

    /// <summary>
    /// Evaluates a record set that was found at one name.
    /// </summary>
    /// <param name="records">The CAA record data, as a resolver returns it, for example <c>0 issue "letsencrypt.org"</c>.</param>
    /// <param name="authorityIdentities">The identities the authority publishes in its directory metadata.</param>
    /// <param name="wildcard">Whether the certificate covers a wildcard name, which gives issuewild precedence.</param>
    /// <returns>The verdict.</returns>
    public static CaaVerdict Evaluate(
        IReadOnlyList<string> records,
        IReadOnlyList<string> authorityIdentities,
        bool wildcard)
    {
        var issue = new List<string>();
        var issueWild = new List<string>();

        foreach (string record in records)
        {
            if (!TryParse(record, out string tag, out string value))
            {
                continue;
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

        foreach (string candidate in relevant)
        {
            if (Names(candidate, authorityIdentities))
            {
                return CaaVerdict.Permitted;
            }
        }

        return CaaVerdict.Forbidden;
    }

    /// <summary>
    /// Splits one record into its tag and value. The flags byte is read past but not used: it marks a
    /// property critical, which matters to an authority deciding whether to refuse, not to this report.
    /// </summary>
    internal static bool TryParse(string record, out string tag, out string value)
    {
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

        tag = parts[1];
        value = parts[2].Trim().Trim('"').Trim();

        return true;
    }

    /// <summary>
    /// Whether an issue value names one of the authority's identities. A value may carry parameters
    /// after a semicolon, such as accounturi, and only the domain before it identifies the authority.
    /// An empty domain is the ";" that forbids everyone.
    /// </summary>
    private static bool Names(string value, IReadOnlyList<string> authorityIdentities)
    {
        int parameters = value.IndexOf(';', StringComparison.Ordinal);
        string domain = (parameters >= 0 ? value[..parameters] : value).Trim();

        if (domain.Length == 0)
        {
            return false;
        }

        foreach (string identity in authorityIdentities)
        {
            if (string.Equals(domain, identity, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
