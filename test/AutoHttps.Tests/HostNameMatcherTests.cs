using AutoHttps.Certificates;
using Xunit;

namespace AutoHttps.Tests;

public class HostNameMatcherTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("example.com", "EXAMPLE.COM")]
    [InlineData("EXAMPLE.com", "example.com")]
    [InlineData("example.com", "example.com.")]
    [InlineData("example.com.", "example.com")]
    public void Matches_ComparesExactNamesWithoutCaseOrTrailingDot(string pattern, string hostName) =>
        Assert.True(HostNameMatcher.Matches(pattern, hostName));

    [Theory]
    [InlineData("example.com", "other.com")]
    [InlineData("example.com", "www.example.com")]
    [InlineData("www.example.com", "example.com")]
    public void Matches_RejectsDifferentNames(string pattern, string hostName) =>
        Assert.False(HostNameMatcher.Matches(pattern, hostName));

    [Theory]
    [InlineData("*.example.com", "www.example.com")]
    [InlineData("*.example.com", "api.example.com")]
    [InlineData("*.EXAMPLE.com", "www.example.com")]
    public void Matches_AcceptsASingleLabelUnderAWildcard(string pattern, string hostName) =>
        Assert.True(HostNameMatcher.Matches(pattern, hostName));

    [Theory]
    [InlineData("*.example.com", "example.com")]
    [InlineData("*.example.com", "a.b.example.com")]
    [InlineData("*.example.com", ".example.com")]
    [InlineData("*.example.com", "wwwexample.com")]
    [InlineData("*.example.com", "other.com")]
    public void Matches_RejectsWhatAWildcardMustNotCover(string pattern, string hostName) =>
        Assert.False(HostNameMatcher.Matches(pattern, hostName));

    [Theory]
    [InlineData("", "example.com")]
    [InlineData("example.com", "")]
    [InlineData("   ", "example.com")]
    public void Matches_RejectsEmptyInput(string pattern, string hostName) =>
        Assert.False(HostNameMatcher.Matches(pattern, hostName));

    [Fact]
    public void Matches_TreatsAnIpAddressAsAnExactName()
    {
        Assert.True(HostNameMatcher.Matches("192.0.2.10", "192.0.2.10"));
        Assert.False(HostNameMatcher.Matches("192.0.2.10", "192.0.2.11"));
    }
}
