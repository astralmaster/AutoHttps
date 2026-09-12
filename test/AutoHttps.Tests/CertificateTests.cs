using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Acme;
using AutoHttps.Certificates;
using AutoHttps.Internal;
using Xunit;

namespace AutoHttps.Tests;

public class CertificateFactoryTests
{
    [Fact]
    public void CreateSigningRequest_PutsEveryIdentifierInTheSubjectAlternativeName()
    {
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        byte[] csr = CertificateFactory.CreateSigningRequest(["example.com", "www.example.com", "*.api.example.com"], key);

        Assert.Equal(
            ["example.com", "www.example.com", "*.api.example.com"],
            ReadDnsNames(csr).ToArray());
    }

    [Fact]
    public void CreateSigningRequest_UsesTheFirstIdentifierAsTheCommonName()
    {
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        byte[] csr = CertificateFactory.CreateSigningRequest(["example.com", "www.example.com"], key);

        CertificateRequest request = CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256);
        Assert.Equal("CN=example.com", request.SubjectName.Name);
    }

    [Fact]
    public void CreateSigningRequest_OmitsACommonNameThatWouldExceedTheDirectoryStringLimit()
    {
        string longName = string.Join('.', Enumerable.Repeat("abcdefghij", 7)) + ".com";
        Assert.True(longName.Length > 64);

        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        byte[] csr = CertificateFactory.CreateSigningRequest([longName], key);

        CertificateRequest request = CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256);
        Assert.Equal(string.Empty, request.SubjectName.Name);
        Assert.Equal([longName], ReadDnsNames(csr).ToArray());
    }

    [Fact]
    public void CreateSigningRequest_EncodesIpIdentifiersAsIpAddressesNotDnsNames()
    {
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        byte[] csr = CertificateFactory.CreateSigningRequest(["192.0.2.10"], key);

        CertificateRequest request = CertificateRequest.LoadSigningRequest(
            csr, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        X509Extension extension = request.CertificateExtensions.Single(e => e.Oid?.Value == "2.5.29.17");
        var subjectAlternativeName = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);

        Assert.Empty(subjectAlternativeName.EnumerateDnsNames());
        Assert.Equal("192.0.2.10", subjectAlternativeName.EnumerateIPAddresses().Single().ToString());
    }

    [Fact]
    public void CreateSigningRequest_RejectsAnEmptyIdentifierList()
    {
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        Assert.Throws<ArgumentException>(() => CertificateFactory.CreateSigningRequest([], key));
    }

    [Theory]
    [InlineData(KeyAlgorithm.EcdsaP256)]
    [InlineData(KeyAlgorithm.EcdsaP384)]
    [InlineData(KeyAlgorithm.Rsa2048)]
    public void CreateSigningRequest_WorksForEverySupportedKeyAlgorithm(KeyAlgorithm algorithm)
    {
        using var key = CertificateKey.Create(algorithm);
        byte[] csr = CertificateFactory.CreateSigningRequest(["example.com"], key);

        Assert.NotEmpty(csr);
        Assert.Equal(["example.com"], ReadDnsNames(csr).ToArray());
    }

    [Fact]
    public void CreateSelfSigned_IsUsableForServerAuthentication()
    {
        using X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            ["example.com"], DateTimeOffset.UtcNow, TimeSpan.FromDays(7));

        Assert.True(certificate.HasPrivateKey);

        var enhancedKeyUsage = (X509EnhancedKeyUsageExtension)certificate.Extensions["2.5.29.37"]!;
        Assert.Contains(enhancedKeyUsage.EnhancedKeyUsages.Cast<Oid>(), oid => oid.Value == "1.3.6.1.5.5.7.3.1");

        var subjectAlternativeName = new X509SubjectAlternativeNameExtension(
            certificate.Extensions["2.5.29.17"]!.RawData, false);
        Assert.Equal(["example.com"], subjectAlternativeName.EnumerateDnsNames().ToArray());
    }

    [Fact]
    public void CreateFromPem_RebuildsALeafWithItsPrivateKeyAndKeepsTheIntermediates()
    {
        using var authority = new TestIssuer();
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        byte[] csr = CertificateFactory.CreateSigningRequest(["example.com", "www.example.com"], key);

        string chainPem = authority.IssueChainPem(csr);

        using ServerCertificate certificate = CertificateFactory.CreateFromPem(chainPem, key.ExportPem());

        Assert.True(certificate.Leaf.HasPrivateKey);
        Assert.Single(certificate.Intermediates);
        Assert.Equal(["example.com", "www.example.com"], certificate.SubjectNames.ToArray());
        Assert.True(certificate.Matches("www.example.com"));
        Assert.False(certificate.Matches("other.example.com"));
    }

    [Fact]
    public void CreateFromPem_RejectsAResponseThatHasNoCertificates() =>
        Assert.Throws<AcmeException>(() => CertificateFactory.CreateFromPem("not a pem", "not a key"));

    [Fact]
    public void CreateFromPem_BuildsAChainContextThatCarriesTheIntermediate()
    {
        using var authority = new TestIssuer();
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        byte[] csr = CertificateFactory.CreateSigningRequest(["example.com"], key);

        using ServerCertificate certificate = CertificateFactory.CreateFromPem(
            authority.IssueChainPem(csr), key.ExportPem());

        Assert.NotNull(certificate.Context);
    }

    private static IEnumerable<string> ReadDnsNames(byte[] csr)
    {
        CertificateRequest request = CertificateRequest.LoadSigningRequest(
            csr, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        X509Extension extension = request.CertificateExtensions.Single(e => e.Oid?.Value == "2.5.29.17");
        return new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical).EnumerateDnsNames();
    }
}

public class AcmeCertificateIdTests
{
    [Fact]
    public void TryCompute_JoinsTheAuthorityKeyIdentifierAndSerialAsRequiredByRfc9773()
    {
        using var authority = new TestIssuer();
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        using X509Certificate2 leaf = authority.Issue(CertificateFactory.CreateSigningRequest(["example.com"], key));

        Assert.True(AcmeCertificateId.TryCompute(leaf, out string certificateId));

        string[] parts = certificateId.Split('.');
        Assert.Equal(2, parts.Length);

        var extension = new X509AuthorityKeyIdentifierExtension(leaf.Extensions["2.5.29.35"]!.RawData, false);
        Assert.Equal(Base64Url.Encode(extension.KeyIdentifier!.Value.Span), parts[0]);

        byte[] serial = leaf.GetSerialNumber();
        Array.Reverse(serial);
        Assert.Equal(Base64Url.Encode(serial), parts[1]);
    }

    [Fact]
    public void TryCompute_IsStableAcrossCalls()
    {
        using var authority = new TestIssuer();
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        using X509Certificate2 leaf = authority.Issue(CertificateFactory.CreateSigningRequest(["example.com"], key));

        Assert.True(AcmeCertificateId.TryCompute(leaf, out string first));
        Assert.True(AcmeCertificateId.TryCompute(leaf, out string second));
        Assert.Equal(first, second);
    }

    [Fact]
    public void TryCompute_ReturnsFalseWhenThereIsNoAuthorityKeyIdentifier()
    {
        using X509Certificate2 selfSigned = CertificateFactory.CreateSelfSigned(
            ["example.com"], DateTimeOffset.UtcNow, TimeSpan.FromDays(1));

        Assert.False(AcmeCertificateId.TryCompute(selfSigned, out string certificateId));
        Assert.Equal(string.Empty, certificateId);
    }

    [Fact]
    public void TryCompute_ProducesDifferentIdsForDifferentCertificates()
    {
        using var authority = new TestIssuer();
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        byte[] csr = CertificateFactory.CreateSigningRequest(["example.com"], key);

        using X509Certificate2 first = authority.Issue(csr);
        using X509Certificate2 second = authority.Issue(csr);

        Assert.True(AcmeCertificateId.TryCompute(first, out string firstId));
        Assert.True(AcmeCertificateId.TryCompute(second, out string secondId));
        Assert.NotEqual(firstId, secondId);
    }

    [Fact]
    public void TryCompute_KeepsTheLeadingZeroOfAHighBitSerial()
    {
        // A serial whose leading octet is >= 0x80 is a positive integer whose DER content octets carry
        // a prepended 0x00. RFC 9773 asks for those content octets, not the minimal magnitude, so the
        // id must include the leading zero. Real serials hit this about half the time; the test issuers
        // used to mask it off, so it went untested.
        byte[] serial = [0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        byte[] authorityKeyIdentifier = [0xDE, 0xAD, 0xBE, 0xEF, 0x01];

        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=high-bit-serial", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(authorityKeyIdentifier));

        using X509Certificate2 certificate = request.Create(
            request.SubjectName,
            X509SignatureGenerator.CreateForECDsa(key),
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            serial);

        // The stored content octets are the 0x00 followed by the sixteen serial bytes.
        byte[] expectedOctets = new byte[serial.Length + 1];
        Array.Copy(serial, 0, expectedOctets, 1, serial.Length);
        Assert.Equal(expectedOctets, certificate.SerialNumberBytes.ToArray());

        Assert.True(AcmeCertificateId.TryCompute(certificate, out string id));

        string[] parts = id.Split('.');
        Assert.Equal(2, parts.Length);
        Assert.Equal(Base64Url.Encode(authorityKeyIdentifier), parts[0]);
        Assert.Equal(Base64Url.Encode(expectedOctets), parts[1]);
    }
}

/// <summary>A minimal two level issuer, so certificate handling can be tested without a network.</summary>
internal sealed class TestIssuer : IDisposable
{
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _intermediate;

    public TestIssuer()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        // Windows caches chain building by subject name, so issuers created by tests running side by
        // side have to be named distinctly or the chain engine starts failing.
        string suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));

        _root = CreateAuthority($"Test Root {suffix}", null, now);
        _intermediate = CreateAuthority($"Test Intermediate {suffix}", _root, now);
    }

    public X509Certificate2 Issue(byte[] signingRequest)
    {
        CertificateRequest request = CertificateRequest.LoadSigningRequest(
            signingRequest, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_intermediate, true, false));

        DateTimeOffset now = DateTimeOffset.UtcNow;
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] = (byte)(serial[0] & 0x7F | 0x01);

        // The issuer signs with its own key regardless of the algorithm the request used, which the
        // convenience overload of Create will not do.
        using ECDsa issuerKey = _intermediate.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("The test intermediate has no private key.");

        return request.Create(
            _intermediate.SubjectName,
            X509SignatureGenerator.CreateForECDsa(issuerKey),
            now.AddMinutes(-5),
            now.AddDays(90),
            serial);
    }

    public string IssueChainPem(byte[] signingRequest)
    {
        using X509Certificate2 leaf = Issue(signingRequest);
        return leaf.ExportCertificatePem() + "\n" + _intermediate.ExportCertificatePem() + "\n";
    }

    public void Dispose()
    {
        _intermediate.Dispose();
        _root.Dispose();
    }

    private static X509Certificate2 CreateAuthority(string name, X509Certificate2? issuer, DateTimeOffset now)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        X509Certificate2 certificate;
        if (issuer is null)
        {
            certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(3650));
        }
        else
        {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            byte[] serial = RandomNumberGenerator.GetBytes(16);
            serial[0] = (byte)(serial[0] & 0x7F | 0x01);

            using X509Certificate2 unsigned = request.Create(issuer, now.AddDays(-1), now.AddDays(1825), serial);
            certificate = unsigned.CopyWithPrivateKey(key);
        }

        byte[] pkcs12 = certificate.Export(X509ContentType.Pkcs12);
        certificate.Dispose();

        try
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12(pkcs12, null, X509KeyStorageFlags.Exportable);
#else
            return new X509Certificate2(pkcs12, (string?)null, X509KeyStorageFlags.Exportable);
#endif
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs12);
        }
    }
}
