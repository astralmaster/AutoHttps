using System;

namespace AutoHttps.Certificates;

internal static class HostNameMatcher
{
    public static bool Matches(string pattern, string hostName)
    {
        ReadOnlySpan<char> subject = Normalize(pattern);
        ReadOnlySpan<char> candidate = Normalize(hostName);

        if (subject.IsEmpty || candidate.IsEmpty)
        {
            return false;
        }

        if (!subject.StartsWith("*.", StringComparison.Ordinal))
        {
            return subject.Equals(candidate, StringComparison.OrdinalIgnoreCase);
        }

        ReadOnlySpan<char> suffix = subject[1..];
        if (!candidate.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        ReadOnlySpan<char> label = candidate[..^suffix.Length];
        return !label.IsEmpty && !label.Contains('.');
    }

    private static ReadOnlySpan<char> Normalize(string value)
    {
        ReadOnlySpan<char> span = value.AsSpan().Trim();
        return span.EndsWith(".", StringComparison.Ordinal) ? span[..^1] : span;
    }
}
