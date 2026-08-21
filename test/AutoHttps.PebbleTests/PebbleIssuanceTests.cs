using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using Xunit;

namespace AutoHttps.PebbleTests;

[Collection(PebbleCollection.Name)]
public class PebbleIssuanceTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(120);

    private readonly PebbleFixture _pebble;

    public PebbleIssuanceTests(PebbleFixture pebble) => _pebble = pebble;

    [Fact]
    public async Task ObtainsACertificateFromPebbleAndServesItOverTls()
    {
        using var storage = new TempStorage();
        string domain = NewDomain();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(domain);
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync(domain, Timeout);

        Assert.Equal([domain], certificate.SubjectNames.ToArray());
        Assert.Contains("Pebble", certificate.Leaf.Issuer, StringComparison.Ordinal);
        Assert.True(certificate.Leaf.HasPrivateKey);

        Assert.True(
            await app.HandshakeIsTrustedAsync(domain, _pebble.PebbleRoot),
            "The certificate Pebble issued did not chain to Pebble's root over a real handshake.");
    }

    [Fact]
    public async Task CoversSeveralDomainsWithOneCertificate()
    {
        using var storage = new TempStorage();
        string primary = NewDomain();
        string secondary = NewDomain();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(primary);
            options.DomainNames.Add(secondary);
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync(primary, Timeout);

        Assert.Equal(2, certificate.SubjectNames.Count);
        Assert.Contains(secondary, certificate.SubjectNames);
        Assert.True(await app.HandshakeIsTrustedAsync(secondary, _pebble.PebbleRoot));
    }

    [Fact]
    public async Task TheRequestedProfileChangesTheCertificatePebbleIssues()
    {
        // Pebble's two profiles issue for ninety days and six days. Requesting each and getting a
        // different lifetime back is what proves the profile reached the authority rather than
        // being quietly dropped. Ordering without a profile is deliberately not asserted on: Pebble
        // then picks one of its profiles at random, so that lifetime is not reproducible.
        TimeSpan withDefaultProfile = await MeasureLifetimeAsync("default");
        TimeSpan withShortLivedProfile = await MeasureLifetimeAsync("shortlived");

        string measured =
            $"default: {withDefaultProfile.TotalDays:F2}d, shortlived: {withShortLivedProfile.TotalDays:F2}d";

        Assert.True(withDefaultProfile.TotalDays is > 89 and < 91, measured);
        Assert.True(withShortLivedProfile.TotalDays is > 5.5 and < 6.5, measured);
    }

    private async Task<TimeSpan> MeasureLifetimeAsync(string? profile)
    {
        using var storage = new TempStorage();
        string domain = NewDomain();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(domain);
            options.Profile = profile;
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync(domain, Timeout);
        return certificate.NotAfter - certificate.NotBefore;
    }

    [Fact]
    public async Task AnUnknownProfileIsReportedRatherThanSilentlyIgnored()
    {
        using var storage = new TempStorage();
        string domain = NewDomain();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(domain);
            options.Profile = "not-a-real-profile";
            options.StorageDirectory = storage.Path;
        });

        await Task.Delay(TimeSpan.FromSeconds(8));

        Assert.Null(app.FindCertificate(domain));
        Assert.True(app.Log.CountOf(110) > 0, "The failed order should have been reported.");
    }

    [Fact]
    public async Task IssuesAWildcardCertificateThroughADnsChallenge()
    {
        using var storage = new TempStorage();
        string zone = NewDomain();
        string wildcard = "*." + zone;

        var dns = new ChallengeTestServerDnsProvider(_pebble);

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(wildcard);
            options.DnsChallengeProvider = dns;
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("anything." + zone, Timeout);

        Assert.Equal([wildcard], certificate.SubjectNames.ToArray());
        Assert.True(certificate.Matches("api." + zone));
        Assert.True(await app.HandshakeIsTrustedAsync("api." + zone, _pebble.PebbleRoot));
        Assert.True(dns.Created > 0);
    }

    [Fact]
    public async Task AsksPebbleWhenToRenewAndActsOnTheAnswer()
    {
        using var storage = new TempStorage();
        string domain = NewDomain();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(domain);
            options.StorageDirectory = storage.Path;
            options.RenewalCheckInterval = TimeSpan.FromSeconds(2);
        });

        await app.WaitForCertificateAsync(domain, Timeout);

        // Event 119 is only logged when the authority returned a renewal window, so seeing it proves
        // the certificate identifier AutoHttps computed was one Pebble recognised.
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (app.Log.CountOf(119) == 0 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(250);
        }

        Assert.True(
            app.Log.CountOf(119) > 0,
            "Pebble never returned renewal information, so the certificate identifier was probably wrong:" +
            Environment.NewLine + app.Log.Describe());
    }

    [Fact]
    public async Task RenewsUnattendedAndKeepsServingTheNewCertificate()
    {
        using var storage = new TempStorage();
        string domain = NewDomain();

        // Waiting out a real renewal window would take days. Renewal falls due once the elapsed part
        // of the lifetime passes (1 - threshold), so on the six day "shortlived" profile a threshold
        // of 0.99999 brings that forward to roughly five seconds. The profile is named explicitly
        // because Pebble picks one at random otherwise, and the arithmetic depends on the lifetime.
        // Everything after that is the ordinary unattended path: the service notices, orders again,
        // swaps the certificate in and writes it to the store, with nobody watching.
        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(domain);
            options.StorageDirectory = storage.Path;
            options.Profile = "shortlived";
            options.UseRenewalInformation = false;
            options.RenewalThreshold = 0.99999;
            options.RenewalCheckInterval = TimeSpan.FromSeconds(2);
        });

        ServerCertificate first = await app.WaitForCertificateAsync(domain, Timeout);
        ServerCertificate renewed = await app.WaitForCertificateChangeAsync(
            domain, first.Leaf.Thumbprint, TimeSpan.FromSeconds(60));

        Assert.NotEqual(first.Leaf.Thumbprint, renewed.Leaf.Thumbprint);
        Assert.Contains("Pebble", renewed.Leaf.Issuer, StringComparison.Ordinal);

        // The renewed certificate has to be the one on the wire, and it has to be on disk.
        Assert.True(await app.HandshakeIsTrustedAsync(domain, _pebble.PebbleRoot));

        string storedChain = await File.ReadAllTextAsync(Directory.GetFiles(storage.Path, "*.crt.pem").Single());
        using X509Certificate2 stored = X509Certificate2.CreateFromPem(storedChain);

        // The threshold above renews every few seconds, so naming one particular renewal here is a
        // race with the next one. What has to hold is that an unattended renewal reached the store
        // rather than only memory, and that the store never goes backwards to an older certificate.
        Assert.NotEqual(first.Leaf.Thumbprint, stored.Thumbprint);
        Assert.True(
            stored.NotBefore >= renewed.Leaf.NotBefore,
            $"The store holds a certificate older than the one already being served: {stored.NotBefore:u} < {renewed.Leaf.NotBefore:u}.");
        Assert.Contains("Pebble", stored.Issuer, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReusesTheStoredCertificateAndAccountAcrossARestart()
    {
        using var storage = new TempStorage();
        string domain = NewDomain();

        string thumbprint;
        await using (PebbleApplication first = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(domain);
            options.StorageDirectory = storage.Path;
        }))
        {
            thumbprint = (await first.WaitForCertificateAsync(domain, Timeout)).Leaf.Thumbprint;
        }

        await using PebbleApplication second = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(domain);
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate reused = await second.WaitForCertificateAsync(domain, Timeout);

        Assert.Equal(thumbprint, reused.Leaf.Thumbprint);
        Assert.Single(Directory.GetFiles(storage.Path, "*.account.pem"));
        Assert.True(await second.HandshakeIsTrustedAsync(domain, _pebble.PebbleRoot));
    }

    [Fact]
    public async Task SurvivesTheNoncesPebbleRandomlyRejects()
    {
        using var storage = new TempStorage();
        var domains = Enumerable.Range(0, 6).Select(_ => NewDomain()).ToArray();

        // Pebble rejects 5% of otherwise good nonces on purpose. Ordering repeatedly makes it very
        // likely that at least one rejection is hit, and every order still has to succeed.
        foreach (string domain in domains)
        {
            using var perDomain = new TempStorage();

            await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
            {
                options.DomainNames.Add(domain);
                options.StorageDirectory = perDomain.Path;
            });

            await app.WaitForCertificateAsync(domain, Timeout);
        }
    }

    [Fact]
    public async Task IssuesAnRsaCertificateWhenAsked()
    {
        using var storage = new TempStorage();
        string domain = NewDomain();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(domain);
            options.KeyAlgorithm = KeyAlgorithm.Rsa2048;
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync(domain, Timeout);

        Assert.Equal("1.2.840.113549.1.1.1", certificate.Leaf.PublicKey.Oid.Value);
        Assert.True(await app.HandshakeIsTrustedAsync(domain, _pebble.PebbleRoot));
    }

    private static string NewDomain() => $"t{Guid.NewGuid():N}"[..12] + ".autohttps.test";

    private sealed class ChallengeTestServerDnsProvider : IDnsChallengeProvider
    {
        private readonly PebbleFixture _pebble;
        private int _created;

        public ChallengeTestServerDnsProvider(PebbleFixture pebble) => _pebble = pebble;

        public int Created => _created;

        public Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _created);
            return _pebble.AddTxtRecordAsync(recordName, recordValue);
        }

        public Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
            _pebble.RemoveTxtRecordAsync(recordName);
    }
}

internal sealed class TempStorage : IDisposable
{
    public TempStorage()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "autohttps-pebble", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
    }
}
