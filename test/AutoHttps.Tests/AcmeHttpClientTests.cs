using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public class AcmeHttpClientTests
{
    private static readonly Uri DirectoryUri = new("https://acme.example.com/directory");

    private const string DirectoryJson = """
        {
          "newNonce": "https://acme.example.com/new-nonce",
          "newAccount": "https://acme.example.com/new-account",
          "newOrder": "https://acme.example.com/new-order",
          "renewalInfo": "https://acme.example.com/renewal-info",
          "meta": { "termsOfService": "https://acme.example.com/terms", "profiles": { "shortlived": "6 days" } }
        }
        """;

    [Fact]
    public async Task GetDirectoryAsync_ParsesEveryEndpointAndTheMetadata()
    {
        var handler = new StubHandler((_, _) => Json(DirectoryJson));
        AcmeHttpClient client = Create(handler, out _);

        AcmeDirectory directory = await client.GetDirectoryAsync(CancellationToken.None);

        Assert.Equal("https://acme.example.com/new-nonce", directory.NewNonce!.AbsoluteUri);
        Assert.Equal("https://acme.example.com/new-order", directory.NewOrder!.AbsoluteUri);
        Assert.Equal("https://acme.example.com/renewal-info", directory.RenewalInfo!.AbsoluteUri);
        Assert.Equal("https://acme.example.com/terms", directory.Meta!.TermsOfService!.AbsoluteUri);
        Assert.Equal("6 days", directory.Meta.Profiles!["shortlived"]);
    }

    [Fact]
    public async Task GetDirectoryAsync_IsFetchedOnceAndCached()
    {
        var handler = new StubHandler((_, _) => Json(DirectoryJson));
        AcmeHttpClient client = Create(handler, out _);

        await client.GetDirectoryAsync(CancellationToken.None);
        await client.GetDirectoryAsync(CancellationToken.None);

        Assert.Equal(1, handler.CountOf("/directory"));
    }

    [Fact]
    public async Task AFourOhFourAgainstAMovedEndpointRefreshesTheDirectoryWithoutARestart()
    {
        int directoryFetches = 0;
        var handler = new StubHandler((request, _) =>
        {
            switch (request.RequestUri!.AbsolutePath)
            {
                case "/directory":
                    string newOrder = ++directoryFetches == 1 ? "/order-v1" : "/order-v2";
                    return Json(DirectoryWith("https://acme.example.com" + newOrder));
                case "/new-nonce":
                    return WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "n");
                case "/order-v1":
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                default:
                    return Json("{}");
            }
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);

        AcmeDirectory stale = await client.GetDirectoryAsync(CancellationToken.None);
        Assert.Equal("https://acme.example.com/order-v1", stale.NewOrder!.AbsoluteUri);

        // The authority moved newOrder and answers 404 at the old URL.
        await Assert.ThrowsAsync<AcmeException>(() => client.PostAsync(
            key, "kid", stale.NewOrder, "{}", AcmeJsonContext.Default.AcmeOrderResource, CancellationToken.None));

        // The next call refetches the directory and picks up the new endpoint, then caches it again.
        AcmeDirectory fresh = await client.GetDirectoryAsync(CancellationToken.None);
        AcmeDirectory reused = await client.GetDirectoryAsync(CancellationToken.None);

        Assert.Equal("https://acme.example.com/order-v2", fresh.NewOrder!.AbsoluteUri);
        Assert.Same(fresh, reused);
        Assert.Equal(2, directoryFetches);
    }

    private static string DirectoryWith(string newOrder) =>
        "{\"newNonce\":\"https://acme.example.com/new-nonce\"," +
        "\"newAccount\":\"https://acme.example.com/new-account\"," +
        "\"newOrder\":\"" + newOrder + "\"," +
        "\"renewalInfo\":\"https://acme.example.com/renewal-info\"}";

    [Fact]
    public async Task PostAsync_FetchesANonceAndSendsItInTheProtectedHeader()
    {
        var handler = new StubHandler((request, _) => request.RequestUri!.AbsolutePath switch
        {
            "/directory" => Json(DirectoryJson),
            "/new-nonce" => WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "nonce-from-head"),
            _ => Json("{}"),
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);
        await client.PostAsync(key, "kid", new Uri("https://acme.example.com/new-order"), "{}", AcmeJsonContext.Default.AcmeOrderResource, CancellationToken.None);

        Assert.Equal("nonce-from-head", ReadHeader(handler.LastBodyFor("/new-order"), "nonce"));

        // Certificate authorities compare this header as an exact string, so an appended charset
        // parameter gets every request rejected with a 415.
        Assert.Equal("application/jose+json", handler.LastContentTypeFor("/new-order"));
        Assert.Empty(handler.LastContentTypeParametersFor("/new-order"));
    }

    [Fact]
    public async Task PostAsync_ReusesTheNonceReturnedWithThePreviousResponse()
    {
        var handler = new StubHandler((request, index) => request.RequestUri!.AbsolutePath switch
        {
            "/directory" => Json(DirectoryJson),
            "/new-nonce" => WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "head-nonce"),
            _ => WithNonce(Json("{}"), "rolling-nonce-" + index),
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);
        var url = new Uri("https://acme.example.com/new-order");

        await client.PostAsync(key, "kid", url, "{}", AcmeJsonContext.Default.AcmeOrderResource, CancellationToken.None);
        await client.PostAsync(key, "kid", url, "{}", AcmeJsonContext.Default.AcmeOrderResource, CancellationToken.None);

        // Only the first request needs a round trip to newNonce.
        Assert.Equal(1, handler.CountOf("/new-nonce"));
        Assert.StartsWith("rolling-nonce-", ReadHeader(handler.LastBodyFor("/new-order"), "nonce"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PostAsync_RetriesWithAFreshNonceWhenTheAuthorityRejectsIt()
    {
        int attempts = 0;
        var handler = new StubHandler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath == "/directory")
            {
                return Json(DirectoryJson);
            }

            if (request.RequestUri.AbsolutePath == "/new-nonce")
            {
                return WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "nonce-" + attempts);
            }

            if (attempts++ == 0)
            {
                return Problem(HttpStatusCode.BadRequest, AcmeErrorTypes.BadNonce, "Bad nonce.");
            }

            return Json("""{"status":"valid"}""");
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);

        AcmeResponse<AcmeOrderResource> response = await client.PostAsync(
            key, "kid", new Uri("https://acme.example.com/new-order"), "{}", AcmeJsonContext.Default.AcmeOrderResource, CancellationToken.None);

        Assert.Equal("valid", response.Content!.Status);
        Assert.Equal(2, handler.CountOf("/new-order"));
    }

    [Fact]
    public async Task PostAsync_GivesUpAfterRepeatedNonceRejections()
    {
        var handler = new StubHandler((request, _) => request.RequestUri!.AbsolutePath switch
        {
            "/directory" => Json(DirectoryJson),
            "/new-nonce" => WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), Guid.NewGuid().ToString("n")),
            _ => Problem(HttpStatusCode.BadRequest, AcmeErrorTypes.BadNonce, "Bad nonce."),
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);

        AcmeException exception = await Assert.ThrowsAsync<AcmeException>(() => client.PostAsync(
            key, "kid", new Uri("https://acme.example.com/new-order"), "{}", AcmeJsonContext.Default.AcmeOrderResource, CancellationToken.None));

        Assert.Contains("repeatedly rejected", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ATransientServerErrorIsRetried()
    {
        int attempts = 0;
        var handler = new StubHandler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath != "/directory")
            {
                return Json("{}");
            }

            return attempts++ < 2
                ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("busy") }
                : Json(DirectoryJson);
        });

        AcmeHttpClient client = Create(handler, out _, out FakeTimeProvider time);

        AcmeDirectory directory = await Complete(time, client.GetDirectoryAsync(CancellationToken.None));

        Assert.Equal("https://acme.example.com/new-order", directory.NewOrder!.AbsoluteUri);
        Assert.Equal(3, handler.CountOf("/directory"));
    }

    [Fact]
    public async Task ARateLimitSurfacesAsARateLimitExceptionCarryingTheRetryAfterTime()
    {
        var handler = new StubHandler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath == "/directory")
            {
                return Json(DirectoryJson);
            }

            if (request.RequestUri.AbsolutePath == "/new-nonce")
            {
                return WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "n");
            }

            HttpResponseMessage response = Problem(
                HttpStatusCode.TooManyRequests, AcmeErrorTypes.RateLimited, "Too many certificates already issued.");
            response.Headers.Add("Retry-After", "600");
            return response;
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key, out FakeTimeProvider time);

        AcmeRateLimitException exception = await Assert.ThrowsAsync<AcmeRateLimitException>(() => client.PostAsync(
            key, "kid", new Uri("https://acme.example.com/new-order"), "{}", AcmeJsonContext.Default.AcmeOrderResource, CancellationToken.None));

        Assert.Equal(AcmeErrorTypes.RateLimited, exception.ErrorType);
        Assert.Equal("Too many certificates already issued.", exception.Detail);
        Assert.Equal(time.GetUtcNow().AddSeconds(600), exception.RetryAfter);
    }

    [Fact]
    public async Task AProblemDocumentIsSurfacedWithItsTypeAndDetail()
    {
        var handler = new StubHandler((request, _) => request.RequestUri!.AbsolutePath switch
        {
            "/directory" => Json(DirectoryJson),
            "/new-nonce" => WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "n"),
            _ => Problem(HttpStatusCode.Forbidden, "urn:ietf:params:acme:error:orderNotReady", "The order is not ready."),
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);

        AcmeException exception = await Assert.ThrowsAsync<AcmeException>(() => client.PostAsync(
            key, "kid", new Uri("https://acme.example.com/finalize"), "{}", AcmeJsonContext.Default.AcmeOrderResource, CancellationToken.None));

        Assert.Equal("urn:ietf:params:acme:error:orderNotReady", exception.ErrorType);
        Assert.Equal("The order is not ready.", exception.Detail);
        Assert.Equal(403, exception.StatusCode);
    }

    [Fact]
    public async Task ATransportFailureIsRetriedAndThenReported()
    {
        var handler = new StubHandler((_, _) => throw new HttpRequestException("connection refused"));
        AcmeHttpClient client = Create(handler, out _, out FakeTimeProvider time);

        AcmeException exception = await Assert.ThrowsAsync<AcmeException>(
            () => Complete(time, client.GetDirectoryAsync(CancellationToken.None)));

        Assert.IsType<HttpRequestException>(exception.InnerException);
        Assert.Equal(5, handler.CountOf("/directory"));
    }

    [Fact]
    public async Task PostAsGetAsync_SendsAnEmptyPayload()
    {
        var handler = new StubHandler((request, _) => request.RequestUri!.AbsolutePath switch
        {
            "/directory" => Json(DirectoryJson),
            "/new-nonce" => WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "n"),
            _ => Json("""{"status":"valid"}"""),
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);
        await client.PostAsGetAsync(key, "kid", new Uri("https://acme.example.com/authz/1"), AcmeJsonContext.Default.AcmeAuthorizationResource, CancellationToken.None);

        using JsonDocument body = JsonDocument.Parse(handler.LastBodyFor("/authz/1"));
        Assert.Equal(string.Empty, body.RootElement.GetProperty("payload").GetString());
    }

    [Fact]
    public async Task PostAsGetRawAsync_ReturnsTheBodyVerbatimAndAsksForTheChainMediaType()
    {
        const string Pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n";

        var handler = new StubHandler((request, _) => request.RequestUri!.AbsolutePath switch
        {
            "/directory" => Json(DirectoryJson),
            "/new-nonce" => WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "n"),
            _ => WithLink(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Pem) },
                "<https://acme.example.com/certificate/1/alt>;rel=\"alternate\""),
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);

        AcmeRawResponse raw = await client.PostAsGetRawAsync(
            key, "kid", new Uri("https://acme.example.com/certificate/1"), "application/pem-certificate-chain", CancellationToken.None);

        Assert.Equal(Pem, raw.Body);
        Assert.Contains("application/pem-certificate-chain", handler.LastAcceptFor("/certificate/1"), StringComparison.Ordinal);
        Assert.Contains(raw.Links, link => link.Relation == "alternate" && link.Url.AbsoluteUri.EndsWith("/alt", StringComparison.Ordinal));
    }

    private static HttpResponseMessage WithLink(HttpResponseMessage response, string link)
    {
        response.Headers.Add("Link", link);
        return response;
    }

    [Fact]
    public async Task LinkHeadersAreParsedIncludingCommasInsideTheUrl()
    {
        var handler = new StubHandler((_, _) =>
        {
            HttpResponseMessage response = Json(DirectoryJson);
            response.Headers.Add("Link", "<https://acme.example.com/terms,v2>;rel=\"terms-of-service\", <https://acme.example.com/index>;rel=\"index\"");
            return response;
        });

        AcmeHttpClient client = Create(handler, out _);

        AcmeResponse<AcmeDirectory> response = await client.GetAsync(DirectoryUri, AcmeJsonContext.Default.AcmeDirectory, CancellationToken.None);

        Assert.Equal(2, response.Links.Count);
        Assert.Equal("https://acme.example.com/terms,v2", response.Links[0].Url.AbsoluteUri);
        Assert.Equal("terms-of-service", response.Links[0].Relation);
        Assert.Equal("index", response.Links[1].Relation);
    }

    [Fact]
    public async Task TheLocationHeaderIsExposedSoTheAccountAndOrderUrlsCanBeCaptured()
    {
        var handler = new StubHandler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath == "/directory")
            {
                return Json(DirectoryJson);
            }

            if (request.RequestUri.AbsolutePath == "/new-nonce")
            {
                return WithNonce(new HttpResponseMessage(HttpStatusCode.NoContent), "n");
            }

            HttpResponseMessage response = Json("{}", HttpStatusCode.Created);
            response.Headers.Location = new Uri("https://acme.example.com/acct/42");
            return response;
        });

        AcmeHttpClient client = Create(handler, out AcmeKey key);

        AcmeResponse<AcmeAccountResource> response = await client.PostAsync(
            key, null, new Uri("https://acme.example.com/new-account"), "{}", AcmeJsonContext.Default.AcmeAccountResource, CancellationToken.None);

        Assert.Equal("https://acme.example.com/acct/42", response.Location!.AbsoluteUri);
    }

    private static AcmeHttpClient Create(StubHandler handler, out AcmeKey key) => Create(handler, out key, out _);

    private static AcmeHttpClient Create(StubHandler handler, out AcmeKey key, out FakeTimeProvider time)
    {
        key = AcmeKey.CreateEcdsa();
        time = new FakeTimeProvider(new DateTimeOffset(2026, 8, 20, 12, 0, 0, TimeSpan.Zero));

        return new AcmeHttpClient(new StubHttpClientFactory(handler), "acme", DirectoryUri, NullLogger.Instance, time);
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;

        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    private static async Task<T> Complete<T>(FakeTimeProvider time, Task<T> task)
    {
        for (int i = 0; i < 400 && !task.IsCompleted; i++)
        {
            await Task.Delay(5);
            time.Advance(TimeSpan.FromSeconds(10));
        }

        return await task;
    }

    private static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Problem(HttpStatusCode status, string type, string detail) =>
        new(status)
        {
            Content = new StringContent(
                string.Create(CultureInfo.InvariantCulture, $$"""{"type":"{{type}}","detail":"{{detail}}","status":{{(int)status}}}"""),
                Encoding.UTF8,
                "application/problem+json"),
        };

    private static HttpResponseMessage WithNonce(HttpResponseMessage response, string nonce)
    {
        response.Headers.Add("Replay-Nonce", nonce);
        return response;
    }

    private static string ReadHeader(string jws, string member)
    {
        using JsonDocument envelope = JsonDocument.Parse(jws);
        string encoded = envelope.RootElement.GetProperty("protected").GetString()!;

        using JsonDocument header = JsonDocument.Parse(Encoding.UTF8.GetString(Base64Url.Decode(encoded)));
        return header.RootElement.GetProperty(member).GetString()!;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, int, HttpResponseMessage> _responder;
        private readonly List<Recorded> _recorded = [];
        private int _index;

        public StubHandler(Func<HttpRequestMessage, int, HttpResponseMessage> responder) => _responder = responder;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);

            lock (_recorded)
            {
                _recorded.Add(new Recorded(
                    request.RequestUri!.AbsolutePath,
                    body,
                    request.Content?.Headers.ContentType?.MediaType,
                    request.Content?.Headers.ContentType?.Parameters.Count ?? 0,
                    string.Join(",", request.Headers.Accept)));
            }

            return _responder(request, Interlocked.Increment(ref _index) - 1);
        }

        public int CountOf(string path)
        {
            lock (_recorded)
            {
                return _recorded.FindAll(r => r.Path == path).Count;
            }
        }

        public string LastBodyFor(string path) => Last(path).Body;

        public string? LastContentTypeFor(string path) => Last(path).ContentType;

        public string LastContentTypeParametersFor(string path) =>
            Last(path).ContentTypeParameterCount == 0 ? string.Empty : "unexpected parameters";

        public string LastAcceptFor(string path) => Last(path).Accept;

        private Recorded Last(string path)
        {
            lock (_recorded)
            {
                return _recorded.FindLast(r => r.Path == path)
                    ?? throw new InvalidOperationException($"No request was made to '{path}'.");
            }
        }

        private sealed record Recorded(string Path, string Body, string? ContentType, int ContentTypeParameterCount, string Accept);
    }
}
