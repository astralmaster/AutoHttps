using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Cloudflare;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.Cloudflare.Tests;

public sealed class CloudflareDnsChallengeProviderTests
{
    private const string Token = "cf-token";

    [Fact]
    public async Task CreatePostsTheRecordToTheConfiguredZoneWithABearerToken()
    {
        var api = new StubApi { Responder = (_, _) => (200, Success("""{"id":"rec1"}""")) };
        CloudflareDnsChallengeProvider provider = Provider(api, o => { o.ApiToken = Token; o.ZoneId = "zone1"; });

        await provider.CreateTxtRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None);

        Recorded post = api.Last(r => r.Method == "POST");
        Assert.Contains("/client/v4/zones/zone1/dns_records", post.Path, StringComparison.Ordinal);
        Assert.Equal("Bearer cf-token", post.Authorization);

        using JsonDocument body = JsonDocument.Parse(post.Body);
        Assert.Equal("TXT", body.RootElement.GetProperty("type").GetString());
        Assert.Equal("_acme-challenge.example.com", body.RootElement.GetProperty("name").GetString());
        Assert.Equal("the-value", body.RootElement.GetProperty("content").GetString());
    }

    [Fact]
    public async Task CreateDiscoversTheZoneFromTheRecordNameWhenNoZoneIdIsSet()
    {
        var api = new StubApi
        {
            Responder = (request, _) =>
            {
                string path = request.RequestUri!.PathAndQuery;
                if (request.Method == HttpMethod.Get && path.Contains("zones?name=example.com", StringComparison.Ordinal))
                {
                    return (200, Success("""[{"id":"zoneX","name":"example.com"}]"""));
                }

                if (request.Method == HttpMethod.Get && path.Contains("zones?name=", StringComparison.Ordinal))
                {
                    return (200, Success("[]"));
                }

                return (200, Success("""{"id":"rec1"}"""));
            },
        };

        CloudflareDnsChallengeProvider provider = Provider(api, o => o.ApiToken = Token);

        await provider.CreateTxtRecordAsync("_acme-challenge.sub.example.com", "value", CancellationToken.None);

        // The two-label registrable name is found after the longer suffix returns nothing.
        Assert.True(api.Count(r => r.Method == "GET" && r.Path.Contains("zones?name=sub.example.com", StringComparison.Ordinal)) > 0);
        Recorded post = api.Last(r => r.Method == "POST");
        Assert.Contains("/zones/zoneX/dns_records", post.Path, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeleteFindsMatchingRecordsAndRemovesThem()
    {
        var api = new StubApi
        {
            Responder = (request, _) =>
            {
                if (request.Method == HttpMethod.Get)
                {
                    return (200, Success("""[{"id":"recA"},{"id":"recB"}]"""));
                }

                return (200, Success("""{"id":"deleted"}"""));
            },
        };

        CloudflareDnsChallengeProvider provider = Provider(api, o => { o.ApiToken = Token; o.ZoneId = "zone1"; });

        await provider.DeleteTxtRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None);

        Assert.Contains(api.Requests, r => r.Method == "DELETE" && r.Path.EndsWith("/dns_records/recA", StringComparison.Ordinal));
        Assert.Contains(api.Requests, r => r.Method == "DELETE" && r.Path.EndsWith("/dns_records/recB", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DeleteDoesNothingWhenNoRecordMatches()
    {
        var api = new StubApi { Responder = (_, _) => (200, Success("[]")) };
        CloudflareDnsChallengeProvider provider = Provider(api, o => { o.ApiToken = Token; o.ZoneId = "zone1"; });

        await provider.DeleteTxtRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None);

        Assert.DoesNotContain(api.Requests, r => r.Method == "DELETE");
    }

    [Fact]
    public async Task AFailedApiResponseIsSurfacedWithItsMessage()
    {
        var api = new StubApi
        {
            Responder = (_, _) => (403, """{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}"""),
        };
        CloudflareDnsChallengeProvider provider = Provider(api, o => { o.ApiToken = Token; o.ZoneId = "zone1"; });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateTxtRecordAsync("_acme-challenge.example.com", "value", CancellationToken.None));

        Assert.Contains("Unauthorized to access requested resource", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AMissingApiTokenIsReported()
    {
        var api = new StubApi();
        CloudflareDnsChallengeProvider provider = Provider(api, o => { o.ApiToken = string.Empty; o.ZoneId = "zone1"; });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.CreateTxtRecordAsync("_acme-challenge.example.com", "value", CancellationToken.None));

        Assert.Contains("ApiToken", error.Message, StringComparison.Ordinal);
    }

    private static CloudflareDnsChallengeProvider Provider(StubApi api, Action<CloudflareDnsOptions> configure)
    {
        var options = new CloudflareDnsOptions();
        configure(options);
        return new CloudflareDnsChallengeProvider(new StubFactory(api), Options.Create(options));
    }

    private static string Success(string result) => $$"""{"success":true,"result":{{result}}}""";

    private sealed record Recorded(string Method, string Path, string Body, string? Authorization);

    private sealed class StubFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public StubFactory(HttpMessageHandler handler) => _handler = handler;

        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    private sealed class StubApi : HttpMessageHandler
    {
        private readonly List<Recorded> _recorded = [];

        public Func<HttpRequestMessage, string, (int Status, string Body)> Responder { get; set; } =
            (_, _) => (200, """{"success":true,"result":{}}""");

        public IReadOnlyList<Recorded> Requests
        {
            get
            {
                lock (_recorded)
                {
                    return _recorded.ToArray();
                }
            }
        }

        public Recorded Last(Func<Recorded, bool> predicate) => Requests.Last(predicate);

        public int Count(Func<Recorded, bool> predicate) => Requests.Count(predicate);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);

            lock (_recorded)
            {
                _recorded.Add(new Recorded(
                    request.Method.Method,
                    request.RequestUri!.PathAndQuery,
                    body,
                    request.Headers.Authorization?.ToString()));
            }

            (int status, string responseBody) = Responder(request, body);
            return new HttpResponseMessage((HttpStatusCode)status)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json"),
            };
        }
    }
}
