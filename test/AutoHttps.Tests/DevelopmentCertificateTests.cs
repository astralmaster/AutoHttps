using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Hosting;
using AutoHttps.Internal;
using Xunit;

namespace AutoHttps.Tests;

public class DevelopmentCertificateTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);
    private const string AspNetHttpsOid = "1.3.6.1.4.1.311.84.1.1";

    [Fact]
    public void TheLocatorPicksTheDevelopmentCertificateAndIgnoresOtherCertificates()
    {
        using X509Certificate2 dev = CreateCertificate(markAsDevelopment: true, Now.AddDays(30));
        using X509Certificate2 other = CreateCertificate(markAsDevelopment: false, Now.AddDays(365));

        X509Certificate2? chosen = DevelopmentCertificateLocator.Select([other, dev], Now);

        Assert.Same(dev, chosen);
    }

    [Fact]
    public void TheLocatorIgnoresAnExpiredDevelopmentCertificate()
    {
        using X509Certificate2 expired = CreateCertificate(markAsDevelopment: true, Now.AddDays(-1));

        Assert.Null(DevelopmentCertificateLocator.Select([expired], Now));
    }

    [Fact]
    public void TheLocatorIgnoresADevelopmentCertificateWithoutAPrivateKey()
    {
        // Kestrel cannot serve a certificate whose private key is not present, so one without a key
        // is not a usable answer even when it carries the right marker.
        using X509Certificate2 noKey = CreateCertificate(markAsDevelopment: true, Now.AddDays(30), withPrivateKey: false);

        Assert.Null(DevelopmentCertificateLocator.Select([noKey], Now));
    }

    [Fact]
    public void TheLocatorPicksTheNewestWhenSeveralAreInstalled()
    {
        using X509Certificate2 older = CreateCertificate(markAsDevelopment: true, Now.AddDays(10));
        using X509Certificate2 newer = CreateCertificate(markAsDevelopment: true, Now.AddDays(60));

        Assert.Same(newer, DevelopmentCertificateLocator.Select([older, newer], Now));
    }

    [Fact]
    public void ADisabledSourceIsNotEnabled() =>
        Assert.False(DevelopmentCertificateSource.Disabled.IsEnabled);

    [Fact]
    public void ASuppliedCertificateSourceReturnsThatCertificate()
    {
        using X509Certificate2 certificate = CreateCertificate(markAsDevelopment: false, Now.AddDays(30));
        DevelopmentCertificateSource source = DevelopmentCertificateSource.FromCertificate(certificate);

        Assert.True(source.IsEnabled);
        Assert.Same(certificate, source.Resolve(Now));
    }

    [Fact]
    public void AFileSourceLoadsThePkcs12()
    {
        using X509Certificate2 certificate = CreateCertificate(markAsDevelopment: false, Now.AddDays(30));
        string path = Path.GetTempFileName();

        try
        {
            File.WriteAllBytes(path, certificate.Export(X509ContentType.Pkcs12, "secret"));

            X509Certificate2? loaded = DevelopmentCertificateSource.FromFile(path, "secret").Resolve(Now);

            Assert.NotNull(loaded);
            Assert.Equal(certificate.Subject, loaded.Subject);
            Assert.True(loaded.HasPrivateKey);
            loaded.Dispose();
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static X509Certificate2 CreateCertificate(bool markAsDevelopment, DateTimeOffset notAfter, bool withPrivateKey = true)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);

        if (markAsDevelopment)
        {
            request.CertificateExtensions.Add(new X509Extension(new Oid(AspNetHttpsOid), [0x05, 0x00], critical: false));
        }

        X509Certificate2 certificate = request.CreateSelfSigned(Now.AddDays(-1), notAfter);

        if (withPrivateKey)
        {
            return certificate;
        }

        X509Certificate2 publicOnly = X509Certificate2.CreateFromPem(certificate.ExportCertificatePem());
        certificate.Dispose();
        return publicOnly;
    }
}
