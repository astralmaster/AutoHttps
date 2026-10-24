using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// A certificate is filed under its exact name set, so a change to the configured names used to find
/// nothing stored and serve the self-signed fallback for every name, including the ones that did not
/// change, until a certificate for the new set was issued. Adding a name whose DNS is not ready yet
/// then took the whole site down for as long as that lasted.
/// </summary>
public sealed class DomainChangeTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    private const int PreviousCertificateServed = 149;
    private const int OrderFailed = 110;

    [Fact]
    public async Task AddingANameThatCannotValidateYetKeepsServingTheNamesThatStayed()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        string original = await IssueAsync(authority, storage, "app.example.com");

        authority.Behavior.UnreachableNames["new.example.com"] = 0;

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            Configure(storage, "app.example.com", "new.example.com"),
            configureServices: services => services.AddHealthChecks().AddAutoHttps());

        // The name that stayed is served its certificate over a real handshake, not the fallback.
        ServerCertificate kept = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        Assert.Equal(original, kept.Leaf.Thumbprint);

        TlsHandshakeResult handshake = await app.HandshakeAsync(
            "app.example.com", authority.RootCertificate, knownIntermediate: authority.IntermediateCertificate);
        Assert.Equal(original, handshake.Leaf.Thumbprint);
        Assert.True(handshake.ChainIsTrusted);

        Assert.Null(app.FindCertificate("new.example.com"));
        Assert.True(app.Log.CountOf(PreviousCertificateServed) > 0, app.Log.Describe());

        // It is not left at that: an order for the full set is attempted, and failing, at once.
        await WaitForEventAsync(app, OrderFailed);

        HealthReportEntry gap = await ReadHealthAsync(app);
        Assert.Equal(HealthStatus.Degraded, gap.Status);
        Assert.Equal("new.example.com", gap.Data["uncovered_domains"]);

        // Once the new name validates, the full set is issued and nothing is left uncovered.
        authority.Behavior.UnreachableNames.Clear();
        ServerCertificate replaced = await app.WaitForCertificateChangeAsync("app.example.com", original, IssuanceTimeout);

        Assert.Equal(
            ["app.example.com", "new.example.com"],
            replaced.SubjectNames.Order(StringComparer.Ordinal).ToArray());

        HealthReportEntry healed = await ReadHealthAsync(app);
        Assert.Equal(HealthStatus.Healthy, healed.Status);
        Assert.False(healed.Data.ContainsKey("uncovered_domains"));
    }

    [Fact]
    public async Task RemovingANameKeepsTheCertificateWithoutOrderingAgain()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        string original = await IssueAsync(authority, storage, "app.example.com", "old.example.com");

        await using (TestApplication narrowed = await TestApplication.StartAsync(authority, Configure(storage, "app.example.com")))
        {
            ServerCertificate kept = await narrowed.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
            Assert.Equal(original, kept.Leaf.Thumbprint);

            await Task.Delay(TimeSpan.FromSeconds(2));
            Assert.Equal(1, authority.OrderCount);
        }

        // The certificate was filed under the narrowed set, so the next start finds it directly
        // rather than through the copy, which another application could have overwritten meanwhile.
        foreach (string latest in Directory.GetFiles(storage.Path, "latest-*"))
        {
            File.Delete(latest);
        }

        await using TestApplication restarted = await TestApplication.StartAsync(authority, Configure(storage, "app.example.com"));
        ServerCertificate reloaded = await restarted.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(original, reloaded.Leaf.Thumbprint);
        Assert.Equal(1, authority.OrderCount);
        Assert.Equal(0, restarted.Log.CountOf(PreviousCertificateServed));
    }

    [Fact]
    public async Task AStoreWrittenBeforeTheCopyExistedGainsOneAtStartup()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        string original = await IssueAsync(authority, storage, "app.example.com");

        // What a store written by an earlier version looks like: the certificate, and no copy.
        foreach (string latest in Directory.GetFiles(storage.Path, "latest-*"))
        {
            File.Delete(latest);
        }

        await using (TestApplication upgraded = await TestApplication.StartAsync(authority, Configure(storage, "app.example.com")))
        {
            await upgraded.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        Assert.NotEmpty(Directory.GetFiles(storage.Path, "latest-*.crt.pem"));

        authority.Behavior.UnreachableNames["new.example.com"] = 0;

        await using TestApplication changed = await TestApplication.StartAsync(
            authority, Configure(storage, "app.example.com", "new.example.com"));

        ServerCertificate kept = await changed.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        Assert.Equal(original, kept.Leaf.Thumbprint);
    }

    [Fact]
    public async Task ACopyCoveringNoneOfTheConfiguredNamesIsNotServed()
    {
        // Several applications on one host share the default storage directory, and so the copy. One
        // whose names are all different must not pick up another's certificate.
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await IssueAsync(authority, storage, "other.example.com");

        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage, "app.example.com"));
        ServerCertificate own = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(["app.example.com"], own.SubjectNames.ToArray());
        Assert.Equal(0, app.Log.CountOf(PreviousCertificateServed));
        Assert.Equal(2, authority.OrderCount);
    }

    [Fact]
    public async Task ChangingTheKeyAlgorithmReplacesTheCertificateStraightAway()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // A 90 day certificate that is nowhere near its renewal point, so only the key can make it due.
        string original = await IssueAsync(authority, storage, "app.example.com");

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage, "app.example.com")(options);
            options.KeyAlgorithm = KeyAlgorithm.Rsa2048;
        });

        ServerCertificate replaced = await app.WaitForCertificateChangeAsync("app.example.com", original, IssuanceTimeout);

        Assert.Equal("1.2.840.113549.1.1.1", replaced.Leaf.PublicKey.Oid.Value);
        Assert.Equal(1, app.Log.CountOf(151));
        Assert.Equal(2, authority.OrderCount);

        // And it settles: the new certificate matches, so nothing else is ordered.
        await Task.Delay(TimeSpan.FromSeconds(2));
        Assert.Equal(2, authority.OrderCount);
    }

    private static async Task<string> IssueAsync(TestCertificateAuthority authority, TempStorage storage, params string[] names)
    {
        await using TestApplication first = await TestApplication.StartAsync(authority, Configure(storage, names));
        return (await first.WaitForCertificateAsync(names[0], IssuanceTimeout)).Leaf.Thumbprint;
    }

    private static Action<AutoHttpsOptions> Configure(TempStorage storage, params string[] names) => options =>
    {
        foreach (string name in names)
        {
            options.DomainNames.Add(name);
        }

        options.StorageDirectory = storage.Path;
    };

    private static async Task<HealthReportEntry> ReadHealthAsync(TestApplication app)
    {
        HealthReport report = await app.Services.GetRequiredService<HealthCheckService>().CheckHealthAsync();
        return report.Entries["autohttps"];
    }

    private static async Task WaitForEventAsync(TestApplication app, int eventId)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + IssuanceTimeout;

        while (app.Log.CountOf(eventId) == 0)
        {
            if (DateTimeOffset.UtcNow > deadline)
            {
                throw new TimeoutException($"Event {eventId} was not logged.{Environment.NewLine}{app.Log.Describe()}");
            }

            await Task.Delay(100);
        }
    }
}
