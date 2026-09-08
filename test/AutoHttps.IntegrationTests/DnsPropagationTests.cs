using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AutoHttps.IntegrationTests;

public sealed class DnsPropagationTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task PollsTheResolverAndValidatesOnceTheRecordIsVisible()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using var resolver = await FakeDohResolver.StartAsync();

        var dns = new ResolverAwareDnsProvider(authority, resolver, publishToResolver: true);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("propagation-seen.example");
            options.PreferredChallengeType = "dns-01";
            options.DnsChallengeProvider = dns;
            options.DnsPropagationResolver = resolver.ResolveUri;
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("propagation-seen.example", Timeout);

        Assert.True(resolver.QueryCount > 0, "The resolver was never queried.");
        Assert.Equal(0, app.Log.CountOf(134));
    }

    [Fact]
    public async Task ProceedsAfterTheTimeoutWhenTheRecordNeverShowsUp()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using var resolver = await FakeDohResolver.StartAsync();

        // The record reaches the authority but never the resolver, so the check has to time out and let
        // the order go ahead rather than blocking issuance on a resolver that never catches up.
        var dns = new ResolverAwareDnsProvider(authority, resolver, publishToResolver: false);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("propagation-missing.example");
            options.PreferredChallengeType = "dns-01";
            options.DnsChallengeProvider = dns;
            options.DnsPropagationResolver = resolver.ResolveUri;
            options.DnsPropagationTimeout = TimeSpan.FromSeconds(1);
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("propagation-missing.example", Timeout);

        Assert.True(app.Log.CountOf(134) > 0, "The propagation timeout was never reported.");
    }

    private sealed class ResolverAwareDnsProvider : IDnsChallengeProvider
    {
        private readonly TestCertificateAuthority _authority;
        private readonly FakeDohResolver _resolver;
        private readonly bool _publishToResolver;

        public ResolverAwareDnsProvider(TestCertificateAuthority authority, FakeDohResolver resolver, bool publishToResolver)
        {
            _authority = authority;
            _resolver = resolver;
            _publishToResolver = publishToResolver;
        }

        public Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
        {
            _authority.Dns.Add(recordName, recordValue);
            if (_publishToResolver)
            {
                _resolver.Add(recordName, recordValue);
            }

            return Task.CompletedTask;
        }

        public Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
        {
            _authority.Dns.Remove(recordName, recordValue);
            return Task.CompletedTask;
        }
    }
}

/// <summary>
/// A minimal DNS-over-HTTPS resolver: it answers the JSON query the propagation checker sends from the
/// records the test has published to it, and counts how many times it was asked.
/// </summary>
internal sealed class FakeDohResolver : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _records =
        new(StringComparer.OrdinalIgnoreCase);

    private int _queries;
    private Uri _baseAddress = new("http://127.0.0.1/");

    private FakeDohResolver(WebApplication app) => _app = app;

    public int QueryCount => Volatile.Read(ref _queries);

    public Uri ResolveUri => new(_baseAddress, "resolve");

    public void Add(string recordName, string recordValue) =>
        _records.GetOrAdd(recordName, static _ => new ConcurrentDictionary<string, byte>(StringComparer.Ordinal))[recordValue] = 0;

    public static async Task<FakeDohResolver> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        WebApplication app = builder.Build();
        var resolver = new FakeDohResolver(app);

        app.MapGet("/resolve", resolver.ResolveAsync);
        await app.StartAsync();

        string address = app.Urls.FirstOrDefault()
            ?? throw new InvalidOperationException("The fake resolver did not bind an address.");
        resolver._baseAddress = new Uri(address.TrimEnd('/') + "/");

        return resolver;
    }

    private Task ResolveAsync(HttpContext context)
    {
        Interlocked.Increment(ref _queries);
        string name = context.Request.Query["name"].ToString();

        var json = new StringBuilder();
        json.Append("{\"Status\":0,\"Answer\":[");

        if (_records.TryGetValue(name, out ConcurrentDictionary<string, byte>? values))
        {
            bool first = true;
            foreach (string value in values.Keys)
            {
                if (!first)
                {
                    json.Append(',');
                }

                first = false;
                json.Append("{\"name\":\"").Append(name).Append("\",\"type\":16,\"data\":\"\\\"").Append(value).Append("\\\"\"}");
            }
        }

        json.Append("]}");

        context.Response.ContentType = "application/dns-json";
        return context.Response.WriteAsync(json.ToString());
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
