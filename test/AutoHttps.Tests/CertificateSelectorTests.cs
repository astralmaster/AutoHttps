using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public class CertificateSelectorTests : IDisposable
{
    private readonly TestIssuer _issuer = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 8, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly CertificateSelector _selector;

    public CertificateSelectorTests() =>
        _selector = new CertificateSelector(NullLogger<CertificateSelector>.Instance, _time);

    public void Dispose()
    {
        _selector.Dispose();
        _issuer.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void WithNothingPublishedAndNoFallbackConfiguredNothingIsServed() =>
        Assert.Null(_selector.Select(null, "example.com"));

    [Fact]
    public void APublishedCertificateIsServedForItsOwnNames()
    {
        _selector.Publish(Issue("example.com", "www.example.com"));

        Assert.NotNull(_selector.Select(null, "example.com"));
        Assert.NotNull(_selector.Select(null, "www.example.com"));
    }

    [Fact]
    public void ARequestForAnUnknownNameIsNotServedAWrongCertificate()
    {
        _selector.Publish(Issue("example.com"));

        Assert.Null(_selector.Select(null, "other.com"));
    }

    [Fact]
    public void AWildcardCertificateCoversItsSubdomains()
    {
        _selector.Publish(Issue("*.example.com"));

        Assert.NotNull(_selector.Select(null, "api.example.com"));
        Assert.Null(_selector.Select(null, "example.com"));
    }

    [Fact]
    public void AClientThatSendsNoServerNameGetsTheFirstCertificate()
    {
        _selector.Publish(Issue("example.com"));

        Assert.NotNull(_selector.Select(null, null));
    }

    [Fact]
    public void PublishingACertificateForTheSameNamesReplacesTheOldOne()
    {
        ServerCertificate first = Issue("example.com");
        _selector.Publish(first);

        ServerCertificate second = Issue("example.com");
        _selector.Publish(second);

        Assert.Equal(second.Leaf.Thumbprint, _selector.Select(null, "example.com")!.Thumbprint);
    }

    [Fact]
    public void CertificatesForUnrelatedNamesCoexist()
    {
        _selector.Publish(Issue("a.example.com"));
        _selector.Publish(Issue("b.example.com"));

        Assert.NotNull(_selector.Select(null, "a.example.com"));
        Assert.NotNull(_selector.Select(null, "b.example.com"));
    }

    [Fact]
    public void AReplacedCertificateStaysUsableUntilItsGracePeriodExpires()
    {
        ServerCertificate first = Issue("example.com");
        _selector.Publish(first);
        _selector.Publish(Issue("example.com"));

        // An in-flight handshake may still hold the old certificate, so disposing it at once would
        // fail live connections.
        _time.Advance(TimeSpan.FromMinutes(1));
        _selector.CollectRetired();
        Assert.Equal(1, _selector.RetiredCount);
        Assert.False(IsDisposed(first.Leaf));

        _time.Advance(TimeSpan.FromMinutes(10));
        _selector.CollectRetired();
        Assert.Equal(0, _selector.RetiredCount);
        Assert.True(IsDisposed(first.Leaf));
    }

    private static bool IsDisposed(X509Certificate2 certificate)
    {
        if (certificate.Handle == IntPtr.Zero)
        {
            return true;
        }

        try
        {
            return certificate.RawData.Length == 0;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return true;
        }
    }

    [Fact]
    public void AFallbackIsServedForConfiguredNamesUntilARealCertificateArrives()
    {
        _selector.SetFallbackNames(["example.com", "www.example.com"]);

        X509Certificate2? fallback = _selector.Select(null, "example.com");

        Assert.NotNull(fallback);
        Assert.Equal(fallback.Subject, fallback.Issuer);
    }

    [Fact]
    public void TheFallbackCoversEveryConfiguredNameRatherThanJustTheFirst()
    {
        _selector.SetFallbackNames(["first.example.com", "second.example.com", "*.third.example.com"]);

        X509Certificate2? served = _selector.Select(null, "second.example.com");
        Assert.NotNull(served);

        var names = new X509SubjectAlternativeNameExtension(served.Extensions["2.5.29.17"]!.RawData, false);

        // Naming only the first domain adds a name mismatch, for every other domain, on top of the
        // untrusted-certificate warning a placeholder already produces.
        Assert.Equal(
            ["*.third.example.com", "first.example.com", "second.example.com"],
            names.EnumerateDnsNames().OrderBy(n => n, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void TheFallbackIsGeneratedOnceAndReused()
    {
        _selector.SetFallbackNames(["example.com"]);

        Assert.Equal(
            _selector.Select(null, "example.com")!.Thumbprint,
            _selector.Select(null, "example.com")!.Thumbprint);
    }

    [Fact]
    public void AnExpiredFallbackIsReplacedRatherThanServedPastItsValidity()
    {
        _selector.SetFallbackNames(["example.com"]);

        X509Certificate2 first = _selector.Select(null, "example.com")!;

        // A first certificate that never arrives leaves the fallback in use past its 14-day lifetime.
        _time.Advance(TimeSpan.FromDays(15));
        X509Certificate2 second = _selector.Select(null, "example.com")!;

        Assert.NotEqual(first.Thumbprint, second.Thumbprint);

        // The replacement is valid at the current time, and still backdated to tolerate clock skew.
        DateTimeOffset now = _time.GetUtcNow();
        Assert.True(second.NotAfter.ToUniversalTime() > now.UtcDateTime);
        Assert.True(second.NotBefore.ToUniversalTime() <= now.AddMinutes(-4).UtcDateTime);

        // The superseded fallback is retired, not dropped mid-handshake, then disposed after the grace period.
        Assert.Equal(1, _selector.RetiredCount);
        _time.Advance(TimeSpan.FromMinutes(6));
        _selector.CollectRetired();
        Assert.Equal(0, _selector.RetiredCount);
        Assert.True(IsDisposed(first));
    }

    [Fact]
    public void NoFallbackIsGeneratedForNamesTheApplicationDoesNotOwn()
    {
        _selector.SetFallbackNames(["example.com"]);

        // Otherwise an attacker could make the process mint a certificate per probed name.
        Assert.Null(_selector.Select(null, "attacker.test"));
    }

    [Fact]
    public void ARealCertificateTakesPrecedenceOverTheFallback()
    {
        _selector.SetFallbackNames(["example.com"]);
        ServerCertificate issued = Issue("example.com");
        _selector.Publish(issued);

        Assert.Equal(issued.Leaf.Thumbprint, _selector.Select(null, "example.com")!.Thumbprint);
    }

    [Fact]
    public void FindExposesTheChainContextForTheListenOptionsIntegration()
    {
        ServerCertificate issued = Issue("example.com");
        _selector.Publish(issued);

        ServerCertificate? found = _selector.Find("example.com");

        Assert.NotNull(found);
        Assert.NotNull(found.Context);
        Assert.Single(found.Intermediates);
    }

    private ServerCertificate Issue(params string[] names)
    {
        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        byte[] csr = CertificateFactory.CreateSigningRequest(names, key);

        return CertificateFactory.CreateFromPem(_issuer.IssueChainPem(csr), key.ExportPem());
    }
}
