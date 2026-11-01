using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// After a key compromise the operator needs a new certificate now, not at the next renewal weeks
/// away. Before RenewAsync the only way was to delete the stored certificate and restart. Every case
/// here also checks that the call returns: a renewal request that can hang leaves an admin endpoint
/// waiting forever.
/// </summary>
public sealed class RenewOnDemandTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(30);

    private const int RenewalRequested = 159;

    [Fact]
    public async Task RenewAsyncServesANewCertificateBeforeItReturns()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await StartAsync(authority, storage);

        string original = (await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;

        // Moments after an issuance, which the guard against ordering in a loop would otherwise hold
        // back for up to an hour. An explicit request is not that loop.
        await Manager(app).RenewAsync().WaitAsync(CallTimeout);

        string served = app.FindCertificate("app.example.com")!.Leaf.Thumbprint;
        Assert.NotEqual(original, served);
        Assert.Equal(2, authority.OrderCount);
        Assert.Equal(1, app.Log.CountOf(RenewalRequested));

        // It settles: the new certificate is not due, so nothing more is ordered.
        await Task.Delay(TimeSpan.FromSeconds(2));
        Assert.Equal(2, authority.OrderCount);
    }

    [Fact]
    public async Task RenewAsyncRevokesThePreviousCertificateOnceTheNewOneIsServed()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await StartAsync(authority, storage);

        string original = (await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;

        await Manager(app).RenewAsync(RevocationReason.KeyCompromise).WaitAsync(CallTimeout);

        Assert.NotEqual(original, app.FindCertificate("app.example.com")!.Leaf.Thumbprint);
        Assert.True(authority.Revocations.TryGetValue(original, out int reason), "The replaced certificate was not revoked.");
        Assert.Equal((int)RevocationReason.KeyCompromise, reason);
        Assert.Single(authority.Revocations);
    }

    [Fact]
    public async Task RequestsMadeTogetherShareOneOrder()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await StartAsync(authority, storage);

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        IAutoHttpsCertificateManager manager = Manager(app);
        await Task.WhenAll(manager.RenewAsync(), manager.RenewAsync(), manager.RenewAsync()).WaitAsync(CallTimeout);

        Assert.Equal(2, authority.OrderCount);
    }

    [Fact]
    public async Task RequestsToReplaceAndRevokeMadeTogetherAllSucceed()
    {
        // A double click on an admin endpoint, or two calls that crossed. They share one order and so
        // one certificate to revoke, and the authority refuses the second revocation as alreadyRevoked.
        // That is the outcome every caller asked for, so none of them may fail over it.
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await StartAsync(authority, storage);

        string original = (await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;

        IAutoHttpsCertificateManager manager = Manager(app);
        await Task.WhenAll(
            manager.RenewAsync(RevocationReason.KeyCompromise),
            manager.RenewAsync(RevocationReason.KeyCompromise)).WaitAsync(CallTimeout);

        Assert.Equal(2, authority.OrderCount);
        Assert.Equal(RevocationReason.KeyCompromise, (RevocationReason)authority.Revocations[original]);
        Assert.Single(authority.Revocations);
    }

    [Fact]
    public async Task EveryInstanceAskedToReplaceEndsOnOneNewCertificate()
    {
        // The documented way to move every instance off a compromised certificate at once: ask each of
        // them. They share the store and its lock, so one orders and the others take what it stored.
        // Validation goes through DNS, because the test authority sends http-01 requests to whichever
        // test application started last, which is not necessarily the one that orders.
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        var dns = new DelegateDnsChallengeProvider(
            (name, value, _) => { authority.Dns.Add(name, value); return Task.CompletedTask; },
            (name, value, _) => { authority.Dns.Remove(name, value); return Task.CompletedTask; });

        Action<AutoHttpsOptions> configure = options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.PreferredChallengeType = "dns-01";
            options.DnsChallengeProvider = dns;
        };

        await using TestApplication first = await TestApplication.StartAsync(authority, configure);
        string original = (await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;
        await using TestApplication second = await TestApplication.StartAsync(authority, configure);
        Assert.Equal(original, (await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint);

        // An instance takes a stored certificate only when it started later than its own, and start
        // times are kept to the second. Without the pause, a fast machine issues the replacement in the
        // same second as the original, and the second instance orders a certificate of its own.
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        await Task.WhenAll(
            Manager(first).RenewAsync(RevocationReason.KeyCompromise),
            Manager(second).RenewAsync(RevocationReason.KeyCompromise)).WaitAsync(TimeSpan.FromSeconds(90));

        string replacement = first.FindCertificate("app.example.com")!.Leaf.Thumbprint;
        Assert.NotEqual(original, replacement);
        Assert.Equal(replacement, second.FindCertificate("app.example.com")!.Leaf.Thumbprint);
        Assert.Equal(2, authority.OrderCount);
        Assert.Equal((int)RevocationReason.KeyCompromise, authority.Revocations[original]);
    }

    [Fact]
    public async Task AFailedRenewalFaultsTheCallAndDoesNotKeepOrdering()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await StartAsync(authority, storage);

        string original = (await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;
        authority.Behavior.FailValidation = true;

        await Assert.ThrowsAsync<AcmeException>(() => Manager(app).RenewAsync().WaitAsync(CallTimeout));

        // The request ended with that attempt. The certificate in use is not due, so the service goes
        // back to its schedule rather than retrying the request on its own.
        int attempts = authority.OrderAttempts;
        authority.Behavior.FailValidation = false;
        await Task.Delay(TimeSpan.FromSeconds(3));

        Assert.Equal(attempts, authority.OrderAttempts);
        Assert.Equal(original, app.FindCertificate("app.example.com")!.Leaf.Thumbprint);
    }

    [Fact]
    public async Task RenewAsyncWhileRateLimitedFaultsWithTheRateLimit()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await StartAsync(authority, storage);

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        authority.Behavior.RateLimitNextOrdersCount = 1;
        authority.Behavior.RateLimitRetryAfter = TimeSpan.FromHours(1);

        IAutoHttpsCertificateManager manager = Manager(app);
        await Assert.ThrowsAsync<AcmeRateLimitException>(() => manager.RenewAsync().WaitAsync(CallTimeout));

        // While the authority's wait lasts, a second request is answered at once with the same reason
        // rather than held for up to an hour.
        int attempts = authority.OrderAttempts;
        AcmeRateLimitException second = await Assert.ThrowsAsync<AcmeRateLimitException>(
            () => manager.RenewAsync().WaitAsync(CallTimeout));

        Assert.NotNull(second.RetryAfter);
        Assert.Equal(attempts, authority.OrderAttempts);
    }

    [Fact]
    public async Task RenewAsyncInDevelopmentThrowsBecauseNothingIsOrdered()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        using X509Certificate2 development = CertificateFactory.CreateSelfSigned(
            ["app.example.com"], DateTimeOffset.UtcNow, TimeSpan.FromDays(1));

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            environment: "Development",
            configureBuilder: builder => builder.UseDevelopmentCertificate(development));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Manager(app).RenewAsync().WaitAsync(CallTimeout));
        Assert.Contains("development", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, authority.OrderCount);
    }

    [Fact]
    public async Task CancellingTheCallStopsTheWaitButNotTheOrder()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await StartAsync(authority, storage);

        string original = (await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;

        // Slow validation, so the order is still running when the caller gives up.
        authority.Behavior.PollsBeforeAuthorizationValid = 20;

        using var caller = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Manager(app).RenewAsync(cancellationToken: caller.Token).WaitAsync(CallTimeout));

        ServerCertificate renewed = await app.WaitForCertificateChangeAsync("app.example.com", original, IssuanceTimeout);
        Assert.NotEqual(original, renewed.Leaf.Thumbprint);
    }

    [Fact]
    public async Task ARequestOutstandingAtShutdownEnds()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        TestApplication app = await StartAsync(authority, storage);

        try
        {
            await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
            authority.Behavior.PollsBeforeAuthorizationValid = int.MaxValue;

            Task request = Manager(app).RenewAsync();
            await Task.Delay(TimeSpan.FromMilliseconds(500));

            await app.StopAsync();

            Exception? ended = await Record.ExceptionAsync(() => request.WaitAsync(CallTimeout));
            Assert.IsAssignableFrom<OperationCanceledException>(ended);
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    private static Task<TestApplication> StartAsync(TestCertificateAuthority authority, TempStorage storage) =>
        TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

    private static IAutoHttpsCertificateManager Manager(TestApplication app) =>
        app.Services.GetRequiredService<IAutoHttpsCertificateManager>();
}
