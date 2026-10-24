using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Route53;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.Route53.Tests;

public sealed class Route53DnsChallengeProviderTests
{
    private const string Name = "_acme-challenge.example.com";

    [Fact]
    public async Task CreateUpsertsAQuotedValueToTheConfiguredZone()
    {
        var route53 = new FakeRoute53();
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);

        FakeRoute53.RecordedChange change = Assert.Single(route53.Changes);
        Assert.Equal("zone1", change.ZoneId);
        Assert.Equal("UPSERT", change.Action);
        Assert.Equal(60, change.Ttl);
        Assert.Equal("\"the-value\"", Assert.Single(change.Values));
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
        Assert.Equal("DELETE", change.Action);
        Assert.Null(route53.Current("zone1", Name));
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

    private static Route53DnsChallengeProvider Provider(FakeRoute53 route53, Action<Route53DnsOptions> configure)
    {
        var options = new Route53DnsOptions();
        configure(options);
        return new Route53DnsChallengeProvider(route53, Options.Create(options));
    }

    /// <summary>
    /// Holds record sets the way Route 53 does: one set of quoted values per name, replaced whole by
    /// an UPSERT, and removed by a DELETE only when it names the set exactly as it stands.
    /// </summary>
    private sealed class FakeRoute53 : IRoute53Client
    {
        private readonly Dictionary<(string Zone, string Name), Route53TxtRecord> _records = [];

        public Func<string, string?> ZoneResolver { get; init; } = _ => "zone-default";

        public List<string> ZoneQueries { get; } = [];

        public List<RecordedChange> Changes { get; } = [];

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

        public Task ChangeTxtAsync(
            string zoneId,
            string recordName,
            string action,
            long ttl,
            IReadOnlyList<string> values,
            CancellationToken cancellationToken)
        {
            Changes.Add(new RecordedChange(zoneId, recordName, action, ttl, values.ToList()));

            if (action == "UPSERT")
            {
                _records[(zoneId, recordName)] = new Route53TxtRecord(ttl, values.ToArray());
                return Task.CompletedTask;
            }

            Route53TxtRecord? current = Current(zoneId, recordName);
            if (current is null || current.Ttl != ttl || !current.Values.SequenceEqual(values))
            {
                throw new InvalidOperationException("InvalidChangeBatch: the DELETE does not match the record set.");
            }

            _records.Remove((zoneId, recordName));
            return Task.CompletedTask;
        }

        internal sealed record RecordedChange(string ZoneId, string Name, string Action, long Ttl, IReadOnlyList<string> Values);
    }
}
