using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;

namespace AutoHttps.Internal;

internal static class DomainNormalizer
{
    private const int MaxNameLength = 253;
    private const int MaxLabelLength = 63;

    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = false };

    public static IReadOnlyList<string> Normalize(IEnumerable<string> identifiers)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();

        foreach (string identifier in identifiers)
        {
            if (TryNormalize(identifier, out string normalized) && seen.Add(normalized))
            {
                result.Add(normalized);
            }
        }

        return result;
    }

    public static bool TryNormalize(string identifier, out string normalized)
    {
        normalized = string.Empty;

        if (string.IsNullOrWhiteSpace(identifier))
        {
            return false;
        }

        string candidate = identifier.Trim().TrimEnd('.');

        if (IPAddress.TryParse(candidate, out IPAddress? address))
        {
            normalized = address.ToString();
            return true;
        }

        bool wildcard = candidate.StartsWith("*.", StringComparison.Ordinal);
        string host = wildcard ? candidate[2..] : candidate;

        if (host.Length == 0 || host.Contains('*', StringComparison.Ordinal))
        {
            return false;
        }

        string ascii;
        try
        {
            ascii = Idn.GetAscii(host);
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (!IsValidHostName(ascii))
        {
            return false;
        }

        normalized = wildcard ? "*." + ascii.ToLowerInvariant() : ascii.ToLowerInvariant();
        return true;
    }

    public static bool IsWildcard(string identifier) => identifier.StartsWith("*.", StringComparison.Ordinal);

    /// <summary>
    /// Normalizes the name of a DNS record rather than a host: labels may also hold underscores, as in
    /// <c>_acme-challenge.validation.example.net</c>, and neither a wildcard nor an IP address is one.
    /// </summary>
    public static bool TryNormalizeRecordName(string name, out string normalized)
    {
        normalized = string.Empty;

        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        string candidate = name.Trim().TrimEnd('.');

        if (candidate.Length is 0 or > MaxNameLength || IPAddress.TryParse(candidate, out _))
        {
            return false;
        }

        string[] labels = candidate.Split('.');
        if (labels.Length < 2)
        {
            return false;
        }

        foreach (string label in labels)
        {
            if (label.Length is 0 or > MaxLabelLength || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }

            foreach (char c in label)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_'))
                {
                    return false;
                }
            }
        }

        normalized = candidate.ToLowerInvariant();
        return true;
    }

    private static bool IsValidHostName(string host)
    {
        if (host.Length is 0 or > MaxNameLength)
        {
            return false;
        }

        ReadOnlySpan<char> remaining = host;
        int labelCount = 0;

        while (!remaining.IsEmpty)
        {
            int separator = remaining.IndexOf('.');
            ReadOnlySpan<char> label = separator < 0 ? remaining : remaining[..separator];
            remaining = separator < 0 ? default : remaining[(separator + 1)..];
            labelCount++;

            if (label.Length is 0 or > MaxLabelLength || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }

            foreach (char c in label)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c != '-')
                {
                    return false;
                }
            }
        }

        return labelCount >= 2 && !host.EndsWith('.');
    }
}
