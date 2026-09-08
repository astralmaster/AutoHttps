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
    [Fact]
    public async Task CreateUpsertsAQuotedValueToTheConfiguredZone()
    {
        var route53 = new FakeRoute53();
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.CreateTxtRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None);

        FakeRoute53.RecordedChange change = Assert.Single(route53.Changes);
        Assert.Equal("zone1", change.ZoneId);
        Assert.Equal("UPSERT", change.Action);
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
    public async Task DeleteReadsTheExistingRecordThenRemovesItExactly()
    {
        var route53 = new FakeRoute53
        {
            ExistingRecord = (_, _) => new Route53TxtRecord(120, ["\"stored-value\""]),
        };
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.DeleteTxtRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None);

        FakeRoute53.RecordedChange change = Assert.Single(route53.Changes);
        Assert.Equal("DELETE", change.Action);
        Assert.Equal(120, change.Ttl);
        Assert.Equal("\"stored-value\"", Assert.Single(change.Values));
    }

    [Fact]
    public async Task DeleteIsANoOpWhenNoRecordExists()
    {
        var route53 = new FakeRoute53 { ExistingRecord = (_, _) => null };
        Route53DnsChallengeProvider provider = Provider(route53, o => o.HostedZoneId = "zone1");

        await provider.DeleteTxtRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None);

        Assert.Empty(route53.Changes);
    }

    private static Route53DnsChallengeProvider Provider(FakeRoute53 route53, Action<Route53DnsOptions> configure)
    {
        var options = new Route53DnsOptions();
        configure(options);
        return new Route53DnsChallengeProvider(route53, Options.Create(options));
    }

    private sealed class FakeRoute53 : IRoute53Client
    {
        public Func<string, string?> ZoneResolver { get; init; } = _ => "zone-default";

        public Func<string, string, Route53TxtRecord?> ExistingRecord { get; init; } = (_, _) => null;

        public List<string> ZoneQueries { get; } = [];

        public List<RecordedChange> Changes { get; } = [];

        public Task<string?> FindZoneIdAsync(string dnsName, CancellationToken cancellationToken)
        {
            ZoneQueries.Add(dnsName);
            return Task.FromResult(ZoneResolver(dnsName));
        }

        public Task<Route53TxtRecord?> GetTxtRecordAsync(string zoneId, string recordName, CancellationToken cancellationToken) =>
            Task.FromResult(ExistingRecord(zoneId, recordName));

        public Task ChangeTxtAsync(
            string zoneId,
            string recordName,
            string action,
            long ttl,
            IReadOnlyList<string> values,
            CancellationToken cancellationToken)
        {
            Changes.Add(new RecordedChange(zoneId, recordName, action, ttl, values.ToList()));
            return Task.CompletedTask;
        }

        internal sealed record RecordedChange(string ZoneId, string Name, string Action, long Ttl, IReadOnlyList<string> Values);
    }
}
