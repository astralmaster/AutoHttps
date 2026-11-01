using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Route53;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Route53.Tests;

public sealed class Route53DnsChallengeProviderTests
{
    private const string Name = "_acme-challenge.example.com";

    [Fact]
    public async Task CreateWritesAQuotedValueToTheConfiguredZone()
    {
        var route53 = new FakeRoute53();
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);

        FakeRoute53.RecordedChange change = Assert.Single(route53.Changes);
        Assert.Equal("zone1", change.ZoneId);
        Assert.Null(change.Expected);
        Assert.Equal(60, change.Replacement!.Ttl);
        Assert.Equal("\"the-value\"", Assert.Single(change.Replacement.Values));
    }

    [Fact]
    public async Task CreateDiscoversTheZoneByWalkingTheRecordNameSuffixes()
    {
        var route53 = new FakeRoute53
        {
            ZoneResolver = name => name == "example.com" ? "zoneX" : null,
        };
        Route53DnsChallengeProvider provider = Provider(route53, _ => { });

        await provider.CreateTxtRecordAsync("_acme-challenge.sub.example.com", "value", CancellationToken.None);

        Assert.Contains("sub.example.com", route53.ZoneQueries);
        Assert.Contains("example.com", route53.ZoneQueries);
        Assert.Equal("zoneX", Assert.Single(route53.Changes).ZoneId);
    }

    [Fact]
    public async Task ADelegatedSubzoneIsUsedEvenAfterItsParentWasCached()
    {
        // example.com and dev.example.com as separate hosted zones, and an order that validates the
        // apex first. A record for dev.example.com written into the parent is never seen, because
        // resolvers follow the delegation to the child zone.
        var route53 = new FakeRoute53
        {
            ZoneResolver = name => name switch
            {
                "example.com" => "parent",
                "dev.example.com" => "child",
                _ => null,
            },
        };
        Route53DnsChallengeProvider provider = Provider(route53, _ => { });

        await provider.CreateTxtRecordAsync("_acme-challenge.example.com", "apex", CancellationToken.None);
        await provider.CreateTxtRecordAsync("_acme-challenge.dev.example.com", "sub", CancellationToken.None);

        Assert.Equal(["parent", "child"], route53.Changes.Select(change => change.ZoneId).ToArray());
    }

    [Fact]
    public async Task AFoundZoneIsRememberedWhileANameThatIsNotAZoneIsAskedAgain()
    {
        var route53 = new FakeRoute53 { ZoneResolver = name => name == "example.com" ? "zoneX" : null };
        Route53DnsChallengeProvider provider = Provider(route53, _ => { });

        await provider.CreateTxtRecordAsync("_acme-challenge.sub.example.com", "one", CancellationToken.None);
        await provider.CreateTxtRecordAsync("_acme-challenge.sub.example.com", "two", CancellationToken.None);

        Assert.Equal(["sub.example.com", "example.com", "sub.example.com"], route53.ZoneQueries.ToArray());
    }

    [Fact]
    public async Task AZoneThatWasNotFoundIsLookedUpAgain()
    {
        // A hosted zone created after the deploy, or a permission granted later, has to be found by the
        // next attempt. A miss remembered for the life of the process failed every later order until a
        // restart, without asking Route 53 again.
        string? zone = null;
        var route53 = new FakeRoute53 { ZoneResolver = name => name == "example.com" ? zone : null };
        Route53DnsChallengeProvider provider = Provider(route53, _ => { });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateTxtRecordAsync(Name, "one", CancellationToken.None));

        zone = "zoneX";
        await provider.CreateTxtRecordAsync(Name, "two", CancellationToken.None);

        Assert.NotNull(route53.Current("zoneX", Name));
    }

    [Fact]
    public async Task ASubdomainDelegatedLaterGetsItsOwnZone()
    {
        string? subzone = null;
        var route53 = new FakeRoute53
        {
            ZoneResolver = name => name switch
            {
                "example.com" => "zoneX",
                "dev.example.com" => subzone,
                _ => null,
            },
        };
        Route53DnsChallengeProvider provider = Provider(route53, _ => { });

        await provider.CreateTxtRecordAsync("_acme-challenge.dev.example.com", "one", CancellationToken.None);
        Assert.NotNull(route53.Current("zoneX", "_acme-challenge.dev.example.com"));

        subzone = "zoneDev";
        await provider.CreateTxtRecordAsync("_acme-challenge.dev.example.com", "two", CancellationToken.None);

        Assert.NotNull(route53.Current("zoneDev", "_acme-challenge.dev.example.com"));
    }

    [Fact]
    public async Task CreateAddsItsValueToTheValuesAlreadyAtTheName()
    {
        // A wildcard and its apex in one order, or another client ordering for the same name, put a
        // second value at the same _acme-challenge name. Replacing the set would fail that validation.
        var route53 = new FakeRoute53();
        route53.Seed("zone1", Name, 300, "\"someone-elses\"");
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Route53TxtRecord stored = route53.Current("zone1", Name)!;
        Assert.Equal(["\"someone-elses\"", "\"the-value\""], stored.Values.ToArray());

        // The set's TTL belongs to whoever created it.
        Assert.Equal(300, stored.Ttl);
    }

    [Fact]
    public async Task CreatingAValueThatIsAlreadyThereChangesNothing()
    {
        var route53 = new FakeRoute53();
        route53.Seed("zone1", Name, 60, "\"the-value\"");
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Assert.Empty(route53.Changes);
    }

    [Fact]
    public async Task DeleteTakesOutOnlyItsOwnValue()
    {
        var route53 = new FakeRoute53();
        route53.Seed("zone1", Name, 300, "\"someone-elses\"", "\"the-value\"");
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Route53TxtRecord stored = route53.Current("zone1", Name)!;
        Assert.Equal(["\"someone-elses\""], stored.Values.ToArray());
        Assert.Equal(300, stored.Ttl);
    }

    [Fact]
    public async Task DeleteRemovesTheSetWhenItsValueWasTheLast()
    {
        var route53 = new FakeRoute53();
        route53.Seed("zone1", Name, 120, "\"the-value\"");
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        FakeRoute53.RecordedChange change = Assert.Single(route53.Changes);
        Assert.Null(change.Replacement);
        Assert.Null(route53.Current("zone1", Name));
    }

    [Fact]
    public async Task AWriterBetweenTheReadAndTheWriteKeepsItsValue()
    {
        // Another deployment ordering for the same name at the same moment, with a lock of its own, reads
        // the same empty set. An unconditional write then drops whichever value was written first, and
        // that order fails validation although Route 53 reported its change as applied.
        var route53 = new FakeRoute53();
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");
        route53.InterfereOnce = () => route53.Seed("zone1", Name, 300, "\"theirs\"");

        await provider.CreateTxtRecordAsync(Name, "ours", CancellationToken.None);

        Route53TxtRecord stored = route53.Current("zone1", Name)!;
        Assert.Equal(["\"ours\"", "\"theirs\""], stored.Values.Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(1, route53.Conflicts);
    }

    [Fact]
    public async Task RemovingOurValueKeepsOneAddedMeanwhile()
    {
        var route53 = new FakeRoute53();
        route53.Seed("zone1", Name, 300, "\"ours\"");
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");
        route53.InterfereOnce = () => route53.Seed("zone1", Name, 300, "\"ours\"", "\"theirs\"");

        await provider.DeleteTxtRecordAsync(Name, "ours", CancellationToken.None);

        Assert.Equal(["\"theirs\""], route53.Current("zone1", Name)!.Values.ToArray());
        Assert.Equal(1, route53.Conflicts);
    }

    [Fact]
    public async Task ARecordSetThatKeepsChangingIsGivenUpAfterFiveAttempts()
    {
        var route53 = new FakeRoute53 { AlwaysInterfere = true };
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateTxtRecordAsync(Name, "ours", CancellationToken.None));

        Assert.Equal(5, route53.Conflicts);
        Assert.Contains(Name, error.Message, StringComparison.Ordinal);
        Assert.Contains("does not match", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeleteLeavesASetThatDoesNotHoldItsValueAlone()
    {
        // Cleanup also runs after a create that never happened, and the set at the name may be
        // someone else's entirely.
        var route53 = new FakeRoute53();
        route53.Seed("zone1", Name, 120, "\"stored-value\"");
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Assert.Empty(route53.Changes);
        Assert.Equal(["\"stored-value\""], route53.Current("zone1", Name)!.Values.ToArray());
    }

    [Fact]
    public async Task DeleteIsANoOpWhenNoRecordExists()
    {
        var route53 = new FakeRoute53();
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Assert.Empty(route53.Changes);
    }

    [Fact]
    public async Task TwoValuesAtOneNameCanBeAddedAndRemovedIndependently()
    {
        var route53 = new FakeRoute53();
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.CreateTxtRecordAsync(Name, "apex", CancellationToken.None);
        await provider.CreateTxtRecordAsync(Name, "wildcard", CancellationToken.None);
        Assert.Equal(["\"apex\"", "\"wildcard\""], route53.Current("zone1", Name)!.Values.ToArray());

        await provider.DeleteTxtRecordAsync(Name, "apex", CancellationToken.None);
        Assert.Equal(["\"wildcard\""], route53.Current("zone1", Name)!.Values.ToArray());

        await provider.DeleteTxtRecordAsync(Name, "wildcard", CancellationToken.None);
        Assert.Null(route53.Current("zone1", Name));
    }

    [Theory]
    [InlineData("AKIDEXAMPLE", null)]
    [InlineData(null, "secret")]
    public void OnlyHalfOfAnExplicitCredentialIsRefused(string? accessKeyId, string? secretAccessKey)
    {
        // Falling back to the default chain here signs in as whatever it finds, an instance role for
        // example, and the failure shows up later as a permission error on that other identity.
        var options = new Route53DnsOptions { AccessKeyId = accessKeyId, SecretAccessKey = secretAccessKey, Region = "us-east-1" };

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => AutoHttpsRoute53BuilderExtensions.CreateClient(options));

        Assert.Contains("AccessKeyId", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnExplicitCredentialWithBothHalvesIsAccepted()
    {
        using Amazon.Route53.AmazonRoute53Client client = AutoHttpsRoute53BuilderExtensions.CreateClient(
            new Route53DnsOptions { AccessKeyId = "AKIDEXAMPLE", SecretAccessKey = "secret", Region = "us-east-1" });

        Assert.NotNull(client);
    }

    [Fact]
    public async Task CreateReturnsOnlyOnceTheChangeIsOnEveryNameServer()
    {
        // Route 53 accepts a change before every name server has it. Asking the authority to validate
        // in that window can reach a name server that is behind and fail the validation.
        var route53 = new FakeRoute53 { PendingChecks = 3 };
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1", time);

        Task create = provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);
        await DriveAsync(create, time);

        Assert.Equal(["/change/C1", "/change/C1", "/change/C1", "/change/C1"], route53.StatusChecks.ToArray());
    }

    [Fact]
    public async Task CreateFailsRatherThanAskingForValidationWhenTheChangeNeverApplies()
    {
        var route53 = new FakeRoute53 { PendingChecks = int.MaxValue };
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1", time);

        Task create = provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() => DriveAsync(create, time));
        Assert.Contains("/change/C1", error.Message, StringComparison.Ordinal);

        // It polled for the whole two minutes and then stopped, rather than giving up early or never.
        int expected = (int)(Route53DnsChallengeProvider.SyncTimeout / Route53DnsChallengeProvider.SyncPollInterval) + 1;
        Assert.Equal(expected, route53.StatusChecks.Count);
    }

    [Fact]
    public async Task DeleteDoesNotWaitForTheChangeToApply()
    {
        // Nothing validates against a removed value, so cleanup has no reason to hold the order up.
        var route53 = new FakeRoute53 { PendingChecks = int.MaxValue };
        route53.Seed("zone1", Name, 60, "\"the-value\"");
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Assert.Empty(route53.StatusChecks);
    }

    // Advances the fake clock one poll interval at a time until the operation finishes, giving its
    // continuation a moment to register the next delay in between.
    private static async Task DriveAsync(Task operation, FakeTimeProvider time)
    {
        for (int step = 0; step < 200 && !operation.IsCompleted; step++)
        {
            await Task.Delay(10);
            time.Advance(Route53DnsChallengeProvider.SyncPollInterval);
        }

        await operation;
    }

    private static Route53DnsChallengeProvider Provider(
        FakeRoute53 route53,
        Action<Route53DnsOptions> configure,
        TimeProvider? time = null)
    {
        var options = new Route53DnsOptions();
        configure(options);
        return new Route53DnsChallengeProvider(route53, Options.Create(options), time);
    }

    /// <summary>
    /// Holds record sets the way Route 53 does: one set of quoted values per name. A change batch is
    /// applied whole or not at all, a DELETE has to name the set exactly as it stands, values and TTL,
    /// and a CREATE fails when a set already exists, so DELETE plus CREATE is a compare-and-swap.
    /// </summary>
    private sealed class FakeRoute53 : IRoute53Client
    {
        private readonly Dictionary<(string Zone, string Name), Route53TxtRecord> _records = [];

        public Func<string, string?> ZoneResolver { get; init; } = _ => "zone-default";

        public List<string> ZoneQueries { get; } = [];

        /// <summary>Every change batch that was applied.</summary>
        public List<RecordedChange> Changes { get; } = [];

        /// <summary>How many change batches were refused because the set no longer matched.</summary>
        public int Conflicts { get; private set; }

        /// <summary>Runs once, just before the next change batch is applied, as another writer would.</summary>
        public Action? InterfereOnce { get; set; }

        /// <summary>Changes the set before every change batch, so no batch ever matches.</summary>
        public bool AlwaysInterfere { get; set; }

        public void Seed(string zoneId, string recordName, long ttl, params string[] values) =>
            _records[(zoneId, recordName)] = new Route53TxtRecord(ttl, values);

        public Route53TxtRecord? Current(string zoneId, string recordName) =>
            _records.TryGetValue((zoneId, recordName), out Route53TxtRecord? record) ? record : null;

        public Task<string?> FindZoneIdAsync(string dnsName, CancellationToken cancellationToken)
        {
            ZoneQueries.Add(dnsName);
            return Task.FromResult(ZoneResolver(dnsName));
        }

        public Task<Route53TxtRecord?> GetTxtRecordAsync(string zoneId, string recordName, CancellationToken cancellationToken) =>
            Task.FromResult(Current(zoneId, recordName));

        /// <summary>How many status checks report a change as still pending before it is in sync.</summary>
        public int PendingChecks { get; set; }

        public List<string> StatusChecks { get; } = [];

        public Task<Route53ChangeResult> TryReplaceTxtAsync(
            string zoneId,
            string recordName,
            Route53TxtRecord? expected,
            Route53TxtRecord? replacement,
            CancellationToken cancellationToken)
        {
            Action? interference = InterfereOnce;
            InterfereOnce = null;
            interference?.Invoke();

            if (AlwaysInterfere)
            {
                Route53TxtRecord? before = Current(zoneId, recordName);
                _records[(zoneId, recordName)] = new Route53TxtRecord(
                    before?.Ttl ?? 60, [.. before?.Values ?? [], "\"other-" + Guid.NewGuid().ToString("n") + "\""]);
            }

            Route53TxtRecord? current = Current(zoneId, recordName);
            bool matches = expected is null
                ? current is null
                : current is not null && current.Ttl == expected.Ttl &&
                  current.Values.Order(StringComparer.Ordinal).SequenceEqual(expected.Values.Order(StringComparer.Ordinal));

            if (!matches)
            {
                Conflicts++;
                return Task.FromResult(new Route53ChangeResult(null, "Tried to change the record set but it does not match."));
            }

            Changes.Add(new RecordedChange(zoneId, recordName, expected, replacement));

            if (replacement is null)
            {
                _records.Remove((zoneId, recordName));
            }
            else
            {
                _records[(zoneId, recordName)] = replacement;
            }

            return Task.FromResult(new Route53ChangeResult("/change/C" + Changes.Count, null));
        }

        public Task<bool> IsChangeInSyncAsync(string changeId, CancellationToken cancellationToken)
        {
            StatusChecks.Add(changeId);

            if (PendingChecks > 0)
            {
                PendingChecks--;
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }

        internal sealed record RecordedChange(string ZoneId, string Name, Route53TxtRecord? Expected, Route53TxtRecord? Replacement);
    }
}
