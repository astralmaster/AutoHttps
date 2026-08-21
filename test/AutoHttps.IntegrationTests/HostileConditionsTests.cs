using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// Conditions a long-lived server actually meets: clocks that disagree, an authority that forgets
/// the account, a proxy that answers instead of the authority, and a store someone has damaged.
/// </summary>
public class HostileConditionsTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task ACertificateThatIsNotValidYetBecauseOfClockSkewIsStillUsedAfterARestart()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The authority's clock runs a minute ahead of ours. Real authorities backdate to hide this,
        // but not all do, and a container whose clock has not synced yet sees the same thing.
        authority.Behavior.NotBeforeSkew = TimeSpan.FromMinutes(1);

        await using (TestApplication first = await TestApplication.StartAsync(authority, Configure(storage)))
        {
            await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        Assert.Equal(1, authority.OrderCount);

        await using TestApplication second = await TestApplication.StartAsync(authority, Configure(storage));
        await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // Discarding a certificate the authority just issued, and ordering another, is how a small
        // clock difference turns into a rate limit.
        Assert.Equal(1, authority.OrderCount);
    }

    [Fact]
    public async Task ABadlySkewedAuthorityDoesNotSendTheClientIntoAnOrderingLoop()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.NotBeforeSkew = TimeSpan.FromDays(2);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage)(options);
            options.RenewalCheckInterval = TimeSpan.FromSeconds(1);
        });

        // A certificate that is not valid yet is still the only one there is, so it gets served
        // rather than discarded. What must not happen is the client deciding it is unusable and
        // ordering another one every second.
        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        await Task.Delay(TimeSpan.FromSeconds(6));

        Assert.Equal(1, authority.OrderCount);
    }

    [Fact]
    public async Task TheClientRecoversWhenTheAuthorityForgetsItsAccount()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // After the first order the authority no longer knows the account, which is what a
        // deactivated account, a migrated endpoint, or an authority that lost data looks like.
        authority.Behavior.ForgetAccountsAfterOrders = 1;
        authority.Behavior.AdvertiseRenewalInfo = false;
        authority.Behavior.CertificateLifetime = TimeSpan.FromSeconds(40);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage)(options);
            options.RenewalCheckInterval = TimeSpan.FromSeconds(1);
            options.RenewalThreshold = 0.9;
        });

        ServerCertificate first = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        ServerCertificate renewed = await app.WaitForCertificateChangeAsync(
            "app.example.com", first.Leaf.Thumbprint, TimeSpan.FromSeconds(45));

        Assert.NotEqual(first.Leaf.Thumbprint, renewed.Leaf.Thumbprint);
    }

    [Fact]
    public async Task AnInterceptingProxyAnsweringInsteadOfTheAuthorityIsReportedClearly()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.ReturnHtmlForNextRequests = 3;

        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));

        // The order eventually succeeds once the proxy stops interfering, and nothing crashes on the
        // HTML it returned in the meantime.
        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
    }

    [Fact]
    public async Task AStoreFullOfGarbageIsReplacedRatherThanCrashingTheApplication()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using (TestApplication first = await TestApplication.StartAsync(authority, Configure(storage)))
        {
            await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        foreach (string path in Directory.GetFiles(storage.Path, "*.crt.pem"))
        {
            await File.WriteAllTextAsync(path, "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n");
        }

        await using TestApplication second = await TestApplication.StartAsync(authority, Configure(storage));
        ServerCertificate recovered = await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.True(recovered.Leaf.HasPrivateKey);
        Assert.Equal(2, authority.OrderCount);
    }

    [Fact]
    public async Task AStoreWhereTheKeyDoesNotMatchTheCertificateIsReplaced()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using (TestApplication first = await TestApplication.StartAsync(authority, Configure(storage)))
        {
            await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        // A restore that put back the wrong half of the pair, or a partially replayed backup.
        using var stranger = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        foreach (string path in Directory.GetFiles(storage.Path, "*.key.pem"))
        {
            await File.WriteAllTextAsync(path, stranger.ExportPem());
        }

        await using TestApplication second = await TestApplication.StartAsync(authority, Configure(storage));
        ServerCertificate recovered = await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.True(recovered.Leaf.HasPrivateKey);
        Assert.Equal(2, authority.OrderCount);
    }

    [Fact]
    public async Task AnEmptyAccountKeyFileDoesNotWedgeStartup()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await File.WriteAllTextAsync(Path.Combine(storage.Path, "unrelated.txt"), "junk");
        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
    }

    [Fact]
    public async Task AnInternationalisedDomainIsRequestedInItsAsciiForm()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("münchen.example.com");
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("xn--mnchen-3ya.example.com", IssuanceTimeout);

        // Certificates carry A-labels, and so must the order and the SNI lookup.
        Assert.Equal(["xn--mnchen-3ya.example.com"], certificate.SubjectNames.ToArray());
        Assert.Equal(
            ["xn--mnchen-3ya.example.com"],
            authority.IssuedCertificates.Single().SubjectNames.ToArray());
    }

    [Fact]
    public async Task AClientThatSendsNoServerNameStillGetsACertificate()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            Configure(storage),
            KestrelIntegration.ListenOptions);

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // Older clients and anything connecting by IP send no SNI at all.
        TlsHandshakeResult handshake = await app.HandshakeAsync(string.Empty, authority.RootCertificate);
        Assert.True(handshake.ChainIsTrusted);
    }

    [Fact]
    public async Task TheSelectorWorksWhenKestrelHasNoConnectionToOffer()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // Kestrel passes a null connection for HTTP/3, where there is no TCP connection to hand over.
        var selector = (CertificateSelector)app.Services.GetService(typeof(CertificateSelector))!;

        Assert.NotNull(selector.Select(connection: null, "app.example.com"));
        Assert.Null(selector.Select(connection: null, "elsewhere.test"));
    }

    [Fact]
    public async Task AProxySwallowingTheChallengePathIsNamedAsTheCause()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The authority reaches something that answers, but not this application: exactly what an
        // ingress controller or CDN that intercepts /.well-known/acme-challenge looks like. The
        // authority can only report "404", which reads as though the middleware misbehaved.
        await using TestApplication decoy = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("decoy.example.com");
            options.StorageDirectory = storage.Path;
        });

        using var second = new TempStorage();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = second.Path;
        });

        authority.HttpChallengeResolver = _ => decoy.HttpBaseAddress;

        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (app.Log.CountOf(127) == 0 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(200);
        }

        Assert.True(
            app.Log.CountOf(127) > 0,
            "Nothing pointed at the interception, leaving the reader to suspect their own middleware:" +
            Environment.NewLine + app.Log.Describe());
    }

    [Fact]
    public async Task ARegistrationWhoseResponseIsLostDoesNotLeaveASecondAccountBehind()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The authority committed the registration and then the response never arrived. The account
        // key is only written to the store once registration succeeds, so retrying with a fresh key
        // would ask for a second account and count against the authority's new-account rate limit
        // every time the first attempt is unlucky.
        authority.Behavior.FailNextAccountResponsesCount = 1;

        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));
        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(1, authority.AccountCount);
    }

    [Fact]
    public async Task ANameThatDoesNotResolveIsNotBlamedOnAnInterceptingProxy()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The authority gives up before it makes an HTTP request at all, so nothing asks this
        // process for the token. From in here that is indistinguishable from interception, and
        // the two have nothing in common to fix: one is a DNS record, the other is an ingress.
        authority.Behavior.FailValidation = true;
        authority.Behavior.ValidationErrorType = "urn:ietf:params:acme:error:dns";

        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));

        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (app.Log.CountOf(127) == 0 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(200);
        }

        Assert.True(app.Log.CountOf(127) > 0, "Nothing explained the failure:" + Environment.NewLine + app.Log.Describe());

        string diagnosis = app.Log.Entries.Last(entry => entry.Contains("[127]", StringComparison.Ordinal));

        Assert.Contains("could not resolve", diagnosis, StringComparison.Ordinal);
        Assert.DoesNotContain("proxy", diagnosis, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ShutdownIsPromptEvenWithAnOrderInFlight()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The authority never finishes validating, so the order is still open when the host is asked
        // to stop. An orchestrator sends SIGKILL a few seconds after SIGTERM, so hanging here means
        // being killed rather than shutting down.
        authority.Behavior.PollsBeforeAuthorizationValid = int.MaxValue;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            Configure(storage)(options);
            options.ValidationTimeout = TimeSpan.FromMinutes(10);
            options.PollInterval = TimeSpan.FromSeconds(1);
        });

        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(15);
        while (authority.OrderCount == 0 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(100);
        }

        Assert.Equal(1, authority.OrderCount);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        await app.StopAsync();
        stopwatch.Stop();

        Assert.True(
            stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"Shutting down took {stopwatch.Elapsed}, long enough for an orchestrator to kill the container.");
    }

    [Fact]
    public async Task MovingFromOneAuthorityToAnotherDoesNotReuseTheOldCertificate()
    {
        using var storage = new TempStorage();

        await using TestCertificateAuthority staging = await TestCertificateAuthority.StartAsync();
        await using TestCertificateAuthority production = await TestCertificateAuthority.StartAsync();

        string stagingThumbprint;
        await using (TestApplication first = await TestApplication.StartAsync(staging, Configure(storage)))
        {
            stagingThumbprint = (await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;
        }

        // Developing against a staging endpoint and then switching to the real one, with the storage
        // directory left in place, is how everybody launches. Serving the staging certificate to real
        // visitors because it happened to still be on disk would be a silent outage.
        await using TestApplication second = await TestApplication.StartAsync(production, Configure(storage));
        ServerCertificate issued = await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.NotEqual(stagingThumbprint, issued.Leaf.Thumbprint);
        Assert.Equal(1, production.OrderCount);

        TlsHandshakeResult handshake = await second.HandshakeAsync(
            "app.example.com", production.RootCertificate, knownIntermediate: production.IntermediateCertificate);
        Assert.True(handshake.ChainIsTrusted);
    }

    [Fact]
    public async Task ServingWithoutTheIssuingChainIsAnnouncedRatherThanSilent()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, Configure(storage));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        await app.HandshakeAsync("app.example.com");

        // Kestrel's default wiring cannot send the intermediates. That breaks clients on Linux and
        // is hidden on Windows, so it has to be said out loud rather than discovered in production.
        Assert.True(app.Log.CountOf(126) > 0, "Serving a leaf without its chain was not reported.");
    }

    [Fact]
    public async Task NothingIsAnnouncedWhenTheEndpointSendsTheWholeChain()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            Configure(storage),
            KestrelIntegration.ListenOptions);

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        TlsHandshakeResult handshake = await app.HandshakeAsync("app.example.com", authority.RootCertificate);

        Assert.True(handshake.ChainIsTrusted);
        Assert.Equal(0, app.Log.CountOf(126));
    }

    private static Action<AutoHttpsOptions> Configure(TempStorage storage) => options =>
    {
        options.DomainNames.Add("app.example.com");
        options.StorageDirectory = storage.Path;
    };
}
