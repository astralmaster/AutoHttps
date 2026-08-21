using System.Collections.Generic;
using System.Linq;
using AutoHttps.Internal;
using Xunit;

namespace AutoHttps.Tests;

public class DomainNormalizerTests
{
    [Theory]
    [InlineData("Example.COM", "example.com")]
    [InlineData("  example.com  ", "example.com")]
    [InlineData("example.com.", "example.com")]
    [InlineData("*.Example.com", "*.example.com")]
    [InlineData("sub.domain.example.com", "sub.domain.example.com")]
    public void TryNormalize_LowercasesAndTrims(string input, string expected)
    {
        Assert.True(DomainNormalizer.TryNormalize(input, out string normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("münchen.de", "xn--mnchen-3ya.de")]
    [InlineData("*.münchen.de", "*.xn--mnchen-3ya.de")]
    [InlineData("日本.example.com", "xn--wgv71a.example.com")]
    public void TryNormalize_ConvertsInternationalNamesToPunycode(string input, string expected)
    {
        Assert.True(DomainNormalizer.TryNormalize(input, out string normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("192.0.2.10", "192.0.2.10")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    public void TryNormalize_KeepsIpAddresses(string input, string expected)
    {
        Assert.True(DomainNormalizer.TryNormalize(input, out string normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("localhost")]
    [InlineData("*.com.")]
    [InlineData("*")]
    [InlineData("*.*.example.com")]
    [InlineData("exa*mple.com")]
    [InlineData("-example.com")]
    [InlineData("example-.com")]
    [InlineData("exam ple.com")]
    [InlineData("example..com")]
    [InlineData("https://example.com")]
    [InlineData("example.com/path")]
    public void TryNormalize_RejectsWhatIsNotADomain(string input) =>
        Assert.False(DomainNormalizer.TryNormalize(input, out _));

    [Fact]
    public void TryNormalize_RejectsALabelLongerThan63Characters() =>
        Assert.False(DomainNormalizer.TryNormalize(new string('a', 64) + ".com", out _));

    [Fact]
    public void TryNormalize_AcceptsALabelOfExactly63Characters() =>
        Assert.True(DomainNormalizer.TryNormalize(new string('a', 63) + ".com", out _));

    [Fact]
    public void Normalize_RemovesDuplicatesCaseInsensitivelyAndPreservesOrder()
    {
        IReadOnlyList<string> result = DomainNormalizer.Normalize(
            ["b.example.com", "A.example.com", "a.EXAMPLE.com", "b.example.com."]);

        Assert.Equal(["b.example.com", "a.example.com"], result.ToArray());
    }

    [Fact]
    public void Normalize_SkipsInvalidEntriesRatherThanThrowing()
    {
        IReadOnlyList<string> result = DomainNormalizer.Normalize(["good.example.com", "not a domain", ""]);

        Assert.Equal(["good.example.com"], result.ToArray());
    }

    [Theory]
    [InlineData("*.example.com", true)]
    [InlineData("example.com", false)]
    public void IsWildcard_DetectsTheLeadingLabel(string identifier, bool expected) =>
        Assert.Equal(expected, DomainNormalizer.IsWildcard(identifier));
}
