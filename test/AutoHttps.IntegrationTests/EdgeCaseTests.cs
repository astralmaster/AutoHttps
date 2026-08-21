using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Xunit;

namespace AutoHttps.IntegrationTests;

public class EdgeCaseTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task IssuesACertificateForAnIpAddress()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("192.0.2.10");
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("192.0.2.10", IssuanceTimeout);

        Assert.Equal(["192.0.2.10"], certificate.SubjectNames.ToArray());
        Assert.True(certificate.Matches("192.0.2.10"));
    }

    [Theory]
    [InlineData(KeyAlgorithm.Rsa2048)]
    [InlineData(KeyAlgorithm.EcdsaP384)]
    public async Task IssuesACertificateForEveryKeyAlgorithm(KeyAlgorithm algorithm)
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.KeyAlgorithm = algorithm;
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        TlsHandshakeResult handshake = await app.HandshakeAsync(
            "app.example.com", authority.RootCertificate, knownIntermediate: authority.IntermediateCertificate);
        Assert.True(handshake.ChainIsTrusted);
    }

    [Fact]
    public async Task SkipsTheChallengeWhenTheAuthorityStillHoldsAValidAuthorization()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.ReuseValidAuthorizations = true;
        authority.Behavior.AdvertiseRenewalInfo = false;
        authority.Behavior.CertificateLifetime = TimeSpan.FromSeconds(30);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.RenewalCheckInterval = TimeSpan.FromMilliseconds(500);
            options.RenewalThreshold = 0.5;
        });

        ServerCertificate first = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // The renewal reuses the authorization the authority already marked valid, so no second
        // challenge response is ever published.
        authority.HttpChallengeResolver = _ => null;

        ServerCertificate renewed = await app.WaitForCertificateChangeAsync(
            "app.example.com", first.Leaf.Thumbprint, TimeSpan.FromSeconds(45));

        Assert.NotEqual(first.Leaf.Thumbprint, renewed.Leaf.Thumbprint);
    }

    [Fact]
    public async Task RecoversWhenFinalizeFailsOnce()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.RejectNextFinalizeCount = 1;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
    }

    [Fact]
    public async Task KeepsServingThroughACertificateReplacement()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.RenewalWindowFactory = _ =>
            (DateTimeOffset.UtcNow.AddDays(30), DateTimeOffset.UtcNow.AddDays(31));

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.RenewalCheckInterval = TimeSpan.FromMilliseconds(300);
        });

        ServerCertificate first = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        using var handshakes = new System.Threading.CancellationTokenSource();
        var failures = new List<Exception>();

        Task load = Task.Run(async () =>
        {
            while (!handshakes.IsCancellationRequested)
            {
                try
                {
                    await app.HandshakeAsync("app.example.com", authority.RootCertificate);
                }
                catch (Exception ex)
                {
                    lock (failures)
                    {
                        failures.Add(ex);
                    }
                }
            }
        });

        authority.Behavior.RenewalWindowFactory = _ =>
            (DateTimeOffset.UtcNow.AddSeconds(-10), DateTimeOffset.UtcNow.AddSeconds(-5));

        await app.WaitForCertificateChangeAsync("app.example.com", first.Leaf.Thumbprint, TimeSpan.FromSeconds(30));
        await Task.Delay(TimeSpan.FromSeconds(1));

        await handshakes.CancelAsync();
        await load;

        // Retiring the replaced certificate immediately would break handshakes that are still using it.
        Assert.Empty(failures);
    }

    [Fact]
    public async Task TheChallengeResponderCanBePlacedInThePipelineByHand()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
                options.HandleHttp01Requests = false;
            },
            manualChallengeMiddleware: true);

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
    }

    [Fact]
    public async Task NoCertificateIsObtainedWhenTheResponderIsTurnedOffEntirely()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.HandleHttp01Requests = false;
        });

        await Task.Delay(TimeSpan.FromSeconds(4));

        Assert.Null(app.FindCertificate("app.example.com"));
        (HttpStatusCode status, _) = await app.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, status);
    }

    [Fact]
    public async Task ManyDomainsAreCoveredByOneCertificate()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        string[] domains = Enumerable.Range(0, 12).Select(i => $"host{i}.example.com").ToArray();

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            foreach (string domain in domains)
            {
                options.DomainNames.Add(domain);
            }

            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync(domains[0], IssuanceTimeout);

        Assert.Equal(domains.Length, certificate.SubjectNames.Count);
        Assert.Equal(1, authority.OrderCount);

        TlsHandshakeResult handshake = await app.HandshakeAsync(
            domains[^1], authority.RootCertificate, knownIntermediate: authority.IntermediateCertificate);
        Assert.True(handshake.ChainIsTrusted);
    }

    [Fact]
    public async Task DuplicateAndDifferentlyCasedDomainsCollapseToOneIdentifier()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("App.Example.com");
            options.DomainNames.Add("app.example.com");
            options.DomainNames.Add("app.example.com.");
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(["app.example.com"], certificate.SubjectNames.ToArray());
    }

    [Fact]
    public async Task KestrelWiringCanBeTurnedOffWithoutStoppingIssuance()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            KestrelIntegration.ListenOptions);

        // ConfigureKestrel is false in this mode, yet the certificate is still obtained and the
        // endpoint that opted in explicitly still serves it.
        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        TlsHandshakeResult handshake = await app.HandshakeAsync("app.example.com", authority.RootCertificate);
        Assert.True(handshake.ChainIsTrusted);
    }
}
