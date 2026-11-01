using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// CNAME delegation: _acme-challenge.example.com is a CNAME of a name in a zone the DNS provider can
/// write, which is how most clients support a DNS host without an API, or one the application should
/// not hold credentials for. The record has to be written at the alias, because the authority follows
/// the CNAME and never looks at the original name.
/// </summary>
public sealed class DnsAliasTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    private const string Alias = "example.com.validation.example.net";

    [Fact]
    public async Task AWildcardAndItsApexAreValidatedThroughTheAlias()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Dns.SetCname("_acme-challenge.example.com", Alias);

        var dns = new NameRecordingProvider(authority);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("*.example.com");
            options.DomainNames.Add("example.com");
            options.PreferredChallengeType = "dns-01";
            options.DnsChallengeProvider = dns;
            options.DnsChallengeAliases["example.com"] = Alias;
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("api.example.com", IssuanceTimeout);

        Assert.True(certificate.Matches("example.com"));
        Assert.Equal([Alias], dns.Written.Distinct().ToArray());
        Assert.Equal(2, dns.Written.Count);
        Assert.Equal(0, authority.Dns.CountFor(Alias));
    }

    [Fact]
    public async Task WithoutTheAliasADelegatedNameDoesNotValidate()
    {
        // The other half of the proof: the authority here really does follow the CNAME, so a record left
        // at the original name is not found, and the alias option is what makes the test above pass.
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Dns.SetCname("_acme-challenge.example.com", Alias);

        var dns = new NameRecordingProvider(authority);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("example.com");
            options.PreferredChallengeType = "dns-01";
            options.DnsChallengeProvider = dns;
            options.StorageDirectory = storage.Path;
        });

        DateTimeOffset deadline = DateTimeOffset.UtcNow + IssuanceTimeout;
        while (app.Log.CountOf(110) == 0 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(100);
        }

        Assert.True(app.Log.CountOf(110) > 0, app.Log.Describe());
        Assert.Null(app.FindCertificate("example.com"));
        Assert.Contains("_acme-challenge.example.com", dns.Written);
    }

    private sealed class NameRecordingProvider : IDnsChallengeProvider
    {
        private readonly TestCertificateAuthority _authority;

        public NameRecordingProvider(TestCertificateAuthority authority) => _authority = authority;

        public ConcurrentQueue<string> Written { get; } = new();

        public Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
        {
            Written.Enqueue(recordName);
            _authority.Dns.Add(recordName, recordValue);
            return Task.CompletedTask;
        }

        public Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
        {
            _authority.Dns.Remove(recordName, recordValue);
            return Task.CompletedTask;
        }
    }
}
