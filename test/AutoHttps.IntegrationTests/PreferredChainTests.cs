using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Xunit;

namespace AutoHttps.IntegrationTests;

public sealed class PreferredChainTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task ServesTheDefaultChainWhenNoPreferenceIsSet()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.OfferAlternateChain = true;

        await using TestApplication app = await TestApplication.StartAsync(
            authority, options => options.DomainNames.Add("preferred-default.example"));

        ServerCertificate certificate = await app.WaitForCertificateAsync("preferred-default.example", Timeout);

        Assert.Equal(authority.RootCommonName, TopIssuer(certificate));
        Assert.Equal(0, app.Log.CountOf(132));
        Assert.Equal(0, app.Log.CountOf(133));
    }

    [Fact]
    public async Task ServesTheAlternateChainWhenPreferredChainMatchesIt()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.OfferAlternateChain = true;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("preferred-alternate.example");
            options.PreferredChain = authority.AlternateRootCommonName;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("preferred-alternate.example", Timeout);

        Assert.Equal(authority.AlternateRootCommonName, TopIssuer(certificate));
        Assert.Equal(1, app.Log.CountOf(132));
    }

    [Fact]
    public async Task FallsBackToTheDefaultChainWhenThePreferenceIsNotOffered()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.OfferAlternateChain = true;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("preferred-missing.example");
            options.PreferredChain = "No Such Root Authority";
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("preferred-missing.example", Timeout);

        Assert.Equal(authority.RootCommonName, TopIssuer(certificate));
        Assert.Equal(1, app.Log.CountOf(133));
    }

    private static string TopIssuer(ServerCertificate certificate)
    {
        X509Certificate2Collection intermediates = certificate.Intermediates;
        X509Certificate2 top = intermediates[intermediates.Count - 1];
        return top.GetNameInfo(X509NameType.SimpleName, forIssuer: true);
    }
}
