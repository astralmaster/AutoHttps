using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Azure;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.Azure.Tests;

public sealed class AzureDnsChallengeProviderTests
{
    [Theory]
    [InlineData("_acme-challenge.example.com", "_acme-challenge")]
    [InlineData("_acme-challenge.sub.example.com", "_acme-challenge.sub")]
    public async Task CreateUpsertsTheNameRelativeToTheZone(string recordName, string expectedRelative)
    {
        var dns = new FakeDns();
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.CreateTxtRecordAsync(recordName, "the-value", CancellationToken.None);

        (string name, long _, string value) = Assert.Single(dns.Upserts);
        Assert.Equal(expectedRelative, name);
        Assert.Equal("the-value", value);
    }

    [Fact]
    public async Task DeletePassesTheRelativeName()
    {
        var dns = new FakeDns();
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.DeleteTxtRecordAsync("_acme-challenge.sub.example.com", "value", CancellationToken.None);

        Assert.Equal("_acme-challenge.sub", Assert.Single(dns.Deletes));
    }

    [Fact]
    public async Task ARecordOutsideTheZoneIsRejected()
    {
        AzureDnsChallengeProvider provider = Provider(new FakeDns(), "example.com");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateTxtRecordAsync("_acme-challenge.somewhere-else.org", "value", CancellationToken.None));
    }

    private static AzureDnsChallengeProvider Provider(FakeDns dns, string zoneName) =>
        new(dns, Options.Create(new AzureDnsOptions { ZoneName = zoneName }));

    private sealed class FakeDns : IAzureDnsClient
    {
        public List<(string Name, long Ttl, string Value)> Upserts { get; } = [];

        public List<string> Deletes { get; } = [];

        public Task UpsertTxtAsync(string relativeRecordName, long ttl, string value, CancellationToken cancellationToken)
        {
            Upserts.Add((relativeRecordName, ttl, value));
            return Task.CompletedTask;
        }

        public Task DeleteTxtAsync(string relativeRecordName, CancellationToken cancellationToken)
        {
            Deletes.Add(relativeRecordName);
            return Task.CompletedTask;
        }
    }
}
