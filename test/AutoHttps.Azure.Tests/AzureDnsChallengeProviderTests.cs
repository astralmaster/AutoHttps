using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Azure;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.Azure.Tests;

public sealed class AzureDnsChallengeProviderTests
{
    private const string Relative = "_acme-challenge";
    private const string Name = "_acme-challenge.example.com";

    [Theory]
    [InlineData("_acme-challenge.example.com", "_acme-challenge")]
    [InlineData("_acme-challenge.sub.example.com", "_acme-challenge.sub")]
    public async Task CreateWritesTheNameRelativeToTheZone(string recordName, string expectedRelative)
    {
        var dns = new FakeDns();
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.CreateTxtRecordAsync(recordName, "the-value", CancellationToken.None);

        AzureTxtRecordSet stored = dns.Current(expectedRelative)!;
        Assert.Equal(["the-value"], Values(stored));
        Assert.Equal(60, stored.Ttl);
    }

    [Fact]
    public async Task ARecordOutsideTheZoneIsRejected()
    {
        AzureDnsChallengeProvider provider = Provider(new FakeDns(), "example.com");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateTxtRecordAsync("_acme-challenge.somewhere-else.org", "value", CancellationToken.None));
    }

    [Fact]
    public async Task CreateAddsItsValueToTheValuesAlreadyAtTheName()
    {
        // A wildcard and its apex in one order, or another client ordering for the same name, put a
        // second value at the same _acme-challenge name. Replacing the set would fail that validation.
        var dns = new FakeDns();
        dns.Seed(Relative, 300, "someone-elses");
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);

        AzureTxtRecordSet stored = dns.Current(Relative)!;
        Assert.Equal(["someone-elses", "the-value"], Values(stored));
        Assert.Equal(300, stored.Ttl);
    }

    [Fact]
    public async Task DeleteTakesOutOnlyItsOwnValue()
    {
        var dns = new FakeDns();
        dns.Seed(Relative, 300, "someone-elses", "the-value");
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Assert.Equal(["someone-elses"], Values(dns.Current(Relative)!));
    }

    [Fact]
    public async Task DeleteRemovesTheSetWhenItsValueWasTheLast()
    {
        var dns = new FakeDns();
        dns.Seed(Relative, 60, "the-value");
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Assert.Null(dns.Current(Relative));
    }

    [Fact]
    public async Task DeleteLeavesASetThatDoesNotHoldItsValueAlone()
    {
        var dns = new FakeDns();
        dns.Seed(Relative, 60, "stored-value");
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Assert.Equal(["stored-value"], Values(dns.Current(Relative)!));
        Assert.Equal(0, dns.Writes);
    }

    [Fact]
    public async Task AValueAddedByAnotherClientBetweenTheReadAndTheWriteIsKept()
    {
        // The write is conditional on the etag that was read. Without that, the other client's value
        // would be overwritten and its validation would fail.
        var dns = new FakeDns();
        dns.Seed(Relative, 60, "first");
        dns.BeforeNextWrite = () => dns.Seed(Relative, 60, "first", "concurrent");
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);

        Assert.Equal(["first", "concurrent", "the-value"], Values(dns.Current(Relative)!));
    }

    [Fact]
    public async Task ASetThatKeepsChangingFailsWithAnExplanationInsteadOfLooping()
    {
        var dns = new FakeDns { AlwaysConflict = true };
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None));

        Assert.Contains("_acme-challenge", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ALongValueStoredInPiecesIsKeptAsItWas()
    {
        // TXT values over 255 characters are stored as several strings. Rewriting the set must not
        // merge or split someone else's record.
        var dns = new FakeDns();
        dns.SeedRecords(Relative, 60, [["part-one", "part-two"]]);
        AzureDnsChallengeProvider provider = Provider(dns, "example.com");

        await provider.CreateTxtRecordAsync(Name, "the-value", CancellationToken.None);
        await provider.DeleteTxtRecordAsync(Name, "the-value", CancellationToken.None);

        IReadOnlyList<string> kept = Assert.Single(dns.Current(Relative)!.Records);
        Assert.Equal(["part-one", "part-two"], kept.ToArray());
    }

    private static string[] Values(AzureTxtRecordSet set) => [.. set.Records.Select(static record => string.Concat(record))];

    private static AzureDnsChallengeProvider Provider(FakeDns dns, string zoneName) =>
        new(dns, Options.Create(new AzureDnsOptions { ZoneName = zoneName }));

    /// <summary>
    /// Holds record sets the way Azure DNS does: one set per name, replaced whole on write, with an etag
    /// that changes on every write and that a conditional write or delete has to match.
    /// </summary>
    private sealed class FakeDns : IAzureDnsClient
    {
        private readonly Dictionary<string, AzureTxtRecordSet> _sets = new(StringComparer.Ordinal);
        private int _version;

        public Action? BeforeNextWrite { get; set; }

        public bool AlwaysConflict { get; init; }

        public int Writes { get; private set; }

        public void Seed(string name, long ttl, params string[] values) =>
            SeedRecords(name, ttl, [.. values.Select(static value => (IReadOnlyList<string>)[value])]);

        public void SeedRecords(string name, long ttl, IReadOnlyList<IReadOnlyList<string>> records) =>
            _sets[name] = new AzureTxtRecordSet(ttl, records, NextETag());

        public AzureTxtRecordSet? Current(string name) => _sets.TryGetValue(name, out AzureTxtRecordSet? set) ? set : null;

        public Task<AzureTxtRecordSet?> GetTxtAsync(string relativeRecordName, CancellationToken cancellationToken) =>
            Task.FromResult(Current(relativeRecordName));

        public Task<bool> TryWriteTxtAsync(
            string relativeRecordName,
            long ttl,
            IReadOnlyList<IReadOnlyList<string>> records,
            string? etag,
            CancellationToken cancellationToken)
        {
            RunInterference();

            if (AlwaysConflict || !Matches(relativeRecordName, etag))
            {
                return Task.FromResult(false);
            }

            Writes++;
            _sets[relativeRecordName] = new AzureTxtRecordSet(ttl, records, NextETag());
            return Task.FromResult(true);
        }

        public Task<bool> TryDeleteTxtAsync(string relativeRecordName, string etag, CancellationToken cancellationToken)
        {
            RunInterference();

            if (AlwaysConflict || !Matches(relativeRecordName, etag))
            {
                return Task.FromResult(false);
            }

            Writes++;
            _sets.Remove(relativeRecordName);
            return Task.FromResult(true);
        }

        private void RunInterference()
        {
            Action? interference = BeforeNextWrite;
            BeforeNextWrite = null;
            interference?.Invoke();
        }

        // With no etag the write is a create, which only succeeds while there is no set.
        private bool Matches(string name, string? etag) =>
            etag is null ? !_sets.ContainsKey(name) : Current(name)?.ETag == etag;

        private string NextETag() => (++_version).ToString(CultureInfo.InvariantCulture);
    }
}
