using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Certificates;
using Xunit;

namespace AutoHttps.Tests;

public sealed class ChainSelectorTests
{
    [Fact]
    public void TopIssuerReadsTheRootTheChainLeadsUpTo()
    {
        (string rootCommonName, string chainPem) = BuildChain();

        Assert.Equal(rootCommonName, ChainSelector.TopIssuer(chainPem));
    }

    [Fact]
    public void MatchesIgnoresCaseAndSurroundingSpace()
    {
        (string rootCommonName, string chainPem) = BuildChain();

        Assert.True(ChainSelector.Matches(chainPem, rootCommonName));
        Assert.True(ChainSelector.Matches(chainPem, "  " + rootCommonName.ToUpperInvariant() + "  "));
    }

    [Fact]
    public void MatchesRejectsADifferentRoot()
    {
        (_, string chainPem) = BuildChain();

        Assert.False(ChainSelector.Matches(chainPem, "Some Other Root"));
    }

    [Fact]
    public void DistinctChainsAreToldApartByTheirRoot()
    {
        (string firstRoot, string firstChain) = BuildChain();
        (string secondRoot, string secondChain) = BuildChain();

        Assert.NotEqual(firstRoot, secondRoot);
        Assert.True(ChainSelector.Matches(firstChain, firstRoot));
        Assert.False(ChainSelector.Matches(firstChain, secondRoot));
        Assert.True(ChainSelector.Matches(secondChain, secondRoot));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a certificate at all")]
    public void UnreadableInputYieldsAPlaceholderRatherThanThrowing(string chainPem)
    {
        Assert.Equal("unknown", ChainSelector.TopIssuer(chainPem));
        Assert.False(ChainSelector.Matches(chainPem, "anything"));
    }

    /// <summary>
    /// Builds a leaf plus its issuing intermediate, in the leaf-first order RFC 8555 uses, and returns
    /// the common name of the root the intermediate was signed by. Every call uses a fresh, unique
    /// root name so two chains are genuinely distinguishable.
    /// </summary>
    private static (string RootCommonName, string ChainPem) BuildChain()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
        string rootCommonName = "Test Root " + suffix;

        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootName = new X500DistinguishedName($"CN={rootCommonName}");
        X509SignatureGenerator rootSigner = X509SignatureGenerator.CreateForECDsa(rootKey);

        using ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest($"CN=Test Intermediate {suffix}", intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, critical: true));
        using X509Certificate2 intermediate = intermediateRequest.Create(rootName, rootSigner, now.AddDays(-1), now.AddDays(1000), Serial());
        X509SignatureGenerator intermediateSigner = X509SignatureGenerator.CreateForECDsa(intermediateKey);

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=leaf.example.test", leafKey, HashAlgorithmName.SHA256);
        using X509Certificate2 leaf = leafRequest.Create(intermediate.SubjectName, intermediateSigner, now.AddDays(-1), now.AddDays(90), Serial());

        string chainPem = leaf.ExportCertificatePem() + "\n" + intermediate.ExportCertificatePem() + "\n";
        return (rootCommonName, chainPem);
    }

    private static byte[] Serial()
    {
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        if (serial[0] == 0)
        {
            serial[0] = 1;
        }

        return serial;
    }
}
