using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.Hosting;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AutoHttps.IntegrationTests;

public class RenewalAndPersistenceTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task AStoredCertificateIsReusedAfterARestartWithoutOrderingAgain()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        string thumbprint;
        await using (TestApplication first = await TestApplication.StartAsync(authority, Configure(storage)))
        {
            thumbprint = (await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;
        }

        Assert.Equal(1, authority.OrderCount);

        await using TestApplication second = await TestApplication.StartAsync(authority, Configure(storage));
        ServerCertificate reused = await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(thumbprint, reused.Leaf.Thumbprint);
        Assert.Equal(1, authority.OrderCount);

        TlsHandshakeResult handshake = await second.HandshakeAsync(
            "app.example.com", authority.RootCertificate, knownIntermediate: authority.IntermediateCertificate);
        Assert.True(handshake.ChainIsTrusted);
    }

    [Fact]
    public async Task TheAccountKeyIsCreatedOnceAndReusedAcrossRestarts()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using (TestApplication first = await TestApplication.StartAsync(authority, Configure(storage)))
        {
            await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        string[] accountKeys = Directory.GetFiles(storage.Path, "*.account.pem");
        Assert.Single(accountKeys);
        string keyMaterial = await File.ReadAllTextAsync(accountKeys[0]);

        // Force a new order so the second process has to register before it can talk to the authority.
        File.Delete(Directory.GetFiles(storage.Path, "*.crt.pem")[0]);

        await using TestApplication second = await TestApplication.StartAsync(authority, Configure(storage));
        await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(keyMaterial, await File.ReadAllTextAsync(accountKeys[0]));
        Assert.Equal(1, authority.AccountCount);
        Assert.Equal(2, authority.OrderCount);
    }

    [Fact]
    public async Task TheCertificateIsOnDiskBeforeItIsEverServed()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // Publishing before persisting leaves a window where a restart loses the certificate and
        // orders another one, which is how an application walks into a duplicate-certificate limit.
        Assert.Single(Directory.GetFiles(storage.Path, "*.crt.pem"));
        Assert.Single(Directory.GetFiles(storage.Path, "*.key.pem"));
    }

    [Fact]
    public async Task ACertificateIsWrittenToTheStoreInAFormOpenSslWouldAccept()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        string chain = await File.ReadAllTextAsync(Directory.GetFiles(storage.Path, "*.crt.pem").Single());
        string key = await File.ReadAllTextAsync(Directory.GetFiles(storage.Path, "*.key.pem").Single());

        Assert.StartsWith("-----BEGIN CERTIFICATE-----", chain, StringComparison.Ordinal);
        Assert.Equal(2, chain.Split("-----BEGIN CERTIFICATE-----").Length - 1);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", key, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASecondInstanceAdoptsTheCertificateInsteadOfOrderingItsOwn()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication first = await TestApplication.StartAsync(authority, Configure(storage));
        ServerCertificate issued = await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        await using TestApplication second = await TestApplication.StartAsync(authority, Configure(storage));
        ServerCertificate adopted = await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(issued.Leaf.Thumbprint, adopted.Leaf.Thumbprint);
        Assert.Equal(1, authority.OrderCount);
    }

    [Fact]
    public async Task RenewsWhenTheAuthoritySaysTheWindowHasOpened()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The first certificate is not due yet; once it exists, the authority moves the suggested
        // window into the immediate future and the client should act on that rather than on its own
        // lifetime heuristic.
        authority.Behavior.RenewalWindowFactory = certificate =>
            (DateTimeOffset.UtcNow.AddDays(30), DateTimeOffset.UtcNow.AddDays(31));

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage)(options);
            options.RenewalCheckInterval = TimeSpan.FromMilliseconds(500);
        });

        ServerCertificate first = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        Assert.Equal(1, authority.OrderCount);

        authority.Behavior.RenewalWindowFactory = _ =>
            (DateTimeOffset.UtcNow.AddSeconds(-10), DateTimeOffset.UtcNow.AddSeconds(-5));

        ServerCertificate renewed = await app.WaitForCertificateChangeAsync(
            "app.example.com", first.Leaf.Thumbprint, TimeSpan.FromSeconds(30));

        Assert.NotEqual(first.Leaf.Thumbprint, renewed.Leaf.Thumbprint);
        Assert.True(authority.OrderCount >= 2);

        TlsHandshakeResult handshake = await app.HandshakeAsync("app.example.com", authority.RootCertificate);
        Assert.Equal(renewed.Leaf.Thumbprint, handshake.Leaf.Thumbprint);
    }

    [Fact]
    public async Task ARenewalTellsTheAuthorityWhichCertificateItReplaces()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.RenewalWindowFactory = _ =>
            (DateTimeOffset.UtcNow.AddDays(30), DateTimeOffset.UtcNow.AddDays(31));

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage)(options);
            options.RenewalCheckInterval = TimeSpan.FromMilliseconds(500);
        });

        ServerCertificate first = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        string expectedId = TestCertificateAuthority.ComputeCertificateId(first.Leaf);

        authority.Behavior.RenewalWindowFactory = _ =>
            (DateTimeOffset.UtcNow.AddSeconds(-10), DateTimeOffset.UtcNow.AddSeconds(-5));

        await app.WaitForCertificateChangeAsync("app.example.com", first.Leaf.Thumbprint, TimeSpan.FromSeconds(30));

        TestIssuedCertificate replacement = authority.IssuedCertificates
            .First(c => c.Leaf.Thumbprint != first.Leaf.Thumbprint);

        // RFC 9773 asks the client to name the certificate being replaced so the authority can grant
        // a renewal exemption from its rate limits.
        Assert.Equal(expectedId, replacement.Replaces);
    }

    [Fact]
    public async Task RecoversWhenTheAuthoritySaysTheCertificateWasAlreadyReplaced()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));

        var acquirer = app.Services.GetRequiredService<CertificateAcquirer>();
        string[] domains = ["renewed.example.com"];

        // A first certificate, then a renewal that names it. The authority now treats the first
        // certificate as replaced and will refuse any later order that names it again.
        CertificateMaterial first = await acquirer.AcquireAsync(domains, replacesCertificateId: null, CancellationToken.None);
        string firstId = CertificateIdOf(first);
        await acquirer.AcquireAsync(domains, firstId, CancellationToken.None);

        // A process killed between finalizing that renewal and writing it to disk comes back still
        // holding the first certificate, so it tries to replace the same one again. The authority
        // answers 409 alreadyReplaced. Naming the replaced certificate is only a rate-limit hint, so
        // the client has to drop it and still obtain a certificate rather than retrying the doomed
        // order until the certificate expires.
        CertificateMaterial recovered = await acquirer.AcquireAsync(domains, firstId, CancellationToken.None);

        using X509Certificate2 leaf = X509Certificate2.CreateFromPem(recovered.CertificateChainPem);
        Assert.Contains("renewed.example.com", DnsNamesOf(leaf));
        Assert.NotEqual(firstId, CertificateIdOf(recovered));
    }

    private static string CertificateIdOf(CertificateMaterial material)
    {
        using X509Certificate2 leaf = X509Certificate2.CreateFromPem(material.CertificateChainPem);
        return TestCertificateAuthority.ComputeCertificateId(leaf);
    }

    private static IEnumerable<string> DnsNamesOf(X509Certificate2 certificate)
    {
        X509Extension? extension = certificate.Extensions["2.5.29.17"];
        return extension is null
            ? []
            : new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical).EnumerateDnsNames();
    }

    [Fact]
    public async Task RenewsOnItsOwnWhenTheAuthorityPublishesNoRenewalInformation()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.AdvertiseRenewalInfo = false;
        authority.Behavior.CertificateLifetime = TimeSpan.FromSeconds(30);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage)(options);
            options.RenewalCheckInterval = TimeSpan.FromMilliseconds(500);
            options.RenewalThreshold = 0.5;
        });

        ServerCertificate first = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        ServerCertificate renewed = await app.WaitForCertificateChangeAsync(
            "app.example.com", first.Leaf.Thumbprint, TimeSpan.FromSeconds(45));

        Assert.NotEqual(first.Leaf.Thumbprint, renewed.Leaf.Thumbprint);
    }

    [Fact]
    public async Task DoesNotSendReplacesToAnAuthorityThatDoesNotAdvertiseRenewalInformation()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The authority advertises no renewalInfo and rejects any order carrying replaces. A renewal
        // that reaches issuance therefore proves the client did not send it (RFC 9773 section 5).
        authority.Behavior.AdvertiseRenewalInfo = false;
        authority.Behavior.CertificateLifetime = TimeSpan.FromSeconds(30);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage)(options);
            options.RenewalCheckInterval = TimeSpan.FromMilliseconds(500);
            options.RenewalThreshold = 0.5;
        });

        ServerCertificate first = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        ServerCertificate renewed = await app.WaitForCertificateChangeAsync(
            "app.example.com", first.Leaf.Thumbprint, TimeSpan.FromSeconds(45));

        Assert.NotEqual(first.Leaf.Thumbprint, renewed.Leaf.Thumbprint);
        Assert.False(authority.SawReplaces);
    }

    [Fact]
    public async Task DoesNotOrderRepeatedlyWhenEveryCertificateLooksDueOnArrival()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.AdvertiseRenewalInfo = false;
        authority.Behavior.CertificateLifetime = TimeSpan.FromSeconds(20);

        // A threshold this high means a certificate qualifies for renewal the moment it is issued.
        // Without a floor between orders this would order continuously until the authority refused.
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage)(options);
            options.RenewalCheckInterval = TimeSpan.FromSeconds(2);
            options.RenewalThreshold = 0.99;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        await Task.Delay(TimeSpan.FromSeconds(6));

        Assert.InRange(authority.OrderCount, 1, 4);
    }

    [Fact]
    public async Task AnExpiredStoredCertificateIsReplacedRatherThanServed()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.CertificateLifetime = TimeSpan.FromSeconds(6);

        await using (TestApplication first = await TestApplication.StartAsync(authority, Configure(storage)))
        {
            await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        await Task.Delay(TimeSpan.FromSeconds(8));

        authority.Behavior.CertificateLifetime = TimeSpan.FromDays(90);

        await using TestApplication second = await TestApplication.StartAsync(authority, Configure(storage));
        ServerCertificate certificate = await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.True(certificate.NotAfter > DateTimeOffset.UtcNow.AddDays(80));
        Assert.Equal(2, authority.OrderCount);
    }

    [Fact]
    public async Task ChangingTheDomainListOrdersANewCertificateRatherThanReusingTheOldOne()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using (TestApplication first = await TestApplication.StartAsync(authority, Configure(storage)))
        {
            await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        await using TestApplication second = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.DomainNames.Add("extra.example.com");
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await second.WaitForCertificateAsync("extra.example.com", IssuanceTimeout);

        Assert.Equal(
            ["app.example.com", "extra.example.com"],
            certificate.SubjectNames.OrderBy(n => n, StringComparer.Ordinal).ToArray());
        Assert.Equal(2, authority.OrderCount);
    }

    private static Action<AutoHttpsOptions> Configure(TempStorage storage) => options =>
    {
        options.DomainNames.Add("app.example.com");
        options.StorageDirectory = storage.Path;
    };
}
