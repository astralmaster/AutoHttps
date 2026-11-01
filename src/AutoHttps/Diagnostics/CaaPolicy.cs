using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

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
/// publicly trusted authority must from 2027-03-15 (CA/Browser Forum ballot SC-098v2). Where the RFCs
/// leave room, records are read the way Boulder, Let's Encrypt's server, reads them (va/caa.go), so a
/// record it refuses is not reported as permitting. This only reports. The authority does the
/// authoritative check, and a client cannot see the same view of DNS that the authority's several
/// validation perspectives do.
/// </summary>
internal static class CaaPolicy
{
    private const string Issue = "issue";
    private const string IssueWild = "issuewild";
    private const string ValidationMethods = "validationmethods";
    private const string AccountUri = "accounturi";

    // Bit 7 (128) is the critical flag of RFC 8659. Boulder also treats bit 0 (1) as critical, because
    // RFC 6844 numbered the bits the other way and records written to that reading exist.
    private const int CriticalFlags = 128 | 1;

    // The tags Boulder understands. It refuses on any other tag that is marked critical.
    private static readonly HashSet<string> KnownTags = new(StringComparer.OrdinalIgnoreCase)
    {
        Issue, IssueWild, "iodef", "issuemail", "issuevmc",
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
            if ((flags & CriticalFlags) != 0 && !KnownTags.Contains(tag))
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
            if (!TrySplit(candidate, out string domain, out List<KeyValuePair<string, string>> parameters) ||
                !Names(domain, authorityIdentities))
            {
                continue;
            }

            // A parameter given twice makes the record permit nothing, as at Boulder, rather than
            // letting one of the two win.
            if (!TryGetSingle(parameters, ValidationMethods, out string? methods) ||
                (methods is not null && !MethodListPermits(methods, challengeType)))
            {
                refusal = Prefer(refusal, CaaVerdict.ForbiddenMethod);
                continue;
            }

            if (!TryGetSingle(parameters, AccountUri, out string? pinned))
            {
                refusal = Prefer(refusal, CaaVerdict.ForbiddenAccount);
                continue;
            }

            if (pinned is not null)
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
    /// empty domain is the ";" that forbids everyone, which names no authority. Parameter names are
    /// kept as written: Boulder matches them case-sensitively, so <c>AccountURI</c> is not accounturi.
    /// A parameter that is not tag=value, a tag that is not letters, digits and inner hyphens, or a
    /// value holding a space or a semicolon makes the record malformed, and Boulder then skips it.
    /// </summary>
    private static bool TrySplit(string value, out string domain, out List<KeyValuePair<string, string>> parameters)
    {
        parameters = [];
        string[] parts = value.Split(';', StringSplitOptions.TrimEntries);

        domain = parts[0];

        for (int i = 1; i < parts.Length; i++)
        {
            // An empty part is what a trailing semicolon leaves, which the RFC 8659 grammar allows.
            if (parts[i].Length == 0)
            {
                continue;
            }

            int equals = parts[i].IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                return false;
            }

            string tag = parts[i][..equals].Trim();
            string parameterValue = parts[i][(equals + 1)..].Trim();

            if (!IsParameterTag(tag) || !parameterValue.All(static c => c is >= '\x21' and <= '\x7e' and not ';'))
            {
                return false;
            }

            parameters.Add(new(tag, parameterValue));
        }

        return domain.Length > 0;
    }

    // Boulder's ^[[:alnum:]](-*[[:alnum:]])*$: alphanumeric at both ends, hyphens only in between.
    private static bool IsParameterTag(string tag) =>
        tag.Length > 0 &&
        char.IsAsciiLetterOrDigit(tag[0]) &&
        char.IsAsciiLetterOrDigit(tag[^1]) &&
        tag.All(static c => char.IsAsciiLetterOrDigit(c) || c == '-');

    /// <summary>
    /// Reads a parameter that may appear once. Returns false when it appears more than once, which
    /// leaves the record unusable. Otherwise <paramref name="value"/> is its value, or null when absent.
    /// </summary>
    private static bool TryGetSingle(List<KeyValuePair<string, string>> parameters, string name, out string? value)
    {
        value = null;

        foreach (KeyValuePair<string, string> parameter in parameters)
        {
            if (!string.Equals(parameter.Key, name, StringComparison.Ordinal))
            {
                continue;
            }

            if (value is not null)
            {
                return false;
            }

            value = parameter.Value;
        }

        return true;
    }

    /// <summary>
    /// Whether a validationmethods list permits the method in use. Boulder splits the list on commas
    /// without trimming and compares exactly, and an entry that is not a method name (letters, digits
    /// and hyphens) makes the whole list permit nothing, so "dns-01, http-01" with its space permits
    /// neither method.
    /// </summary>
    private static bool MethodListPermits(string list, string method)
    {
        bool found = false;

        foreach (string entry in list.Split(','))
        {
            if (entry.Length == 0 || !entry.All(static c => char.IsAsciiLetterOrDigit(c) || c == '-'))
            {
                return false;
            }

            found |= string.Equals(entry, method, StringComparison.Ordinal);
        }

        return found;
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

    // A record that names the authority says more about why issuance would fail than one that does not,
    // so the reason it gives is kept over the plain refusal. One pinned to an account that cannot be
    // checked yet may still permit this order, so that outweighs a definite refusal by another record.
    private static CaaVerdict Prefer(CaaVerdict current, CaaVerdict candidate) =>
        current == CaaVerdict.Forbidden || candidate == CaaVerdict.UnverifiedAccount ? candidate : current;
}
