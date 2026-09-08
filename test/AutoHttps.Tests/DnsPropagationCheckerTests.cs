using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Challenges;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public sealed class DnsPropagationCheckerTests
{
    [Theory]
    [InlineData("https://dns.google/resolve", "https://dns.google/resolve?name=_acme-challenge.example.com&type=TXT")]
    [InlineData("https://cloudflare-dns.com/dns-query", "https://cloudflare-dns.com/dns-query?name=_acme-challenge.example.com&type=TXT")]
    public void BuildQueryUriAppendsNameAndType(string resolver, string expected)
    {
        Uri uri = DnsPropagationChecker.BuildQueryUri(new Uri(resolver), "_acme-challenge.example.com");

        Assert.Equal(expected, uri.AbsoluteUri);
    }

    [Fact]
    public void BuildQueryUriKeepsAnExistingQuery()
    {
        Uri uri = DnsPropagationChecker.BuildQueryUri(new Uri("https://doh.example/q?edns=1"), "a.b");

        Assert.Contains("edns=1", uri.Query, StringComparison.Ordinal);
        Assert.Contains("name=a.b", uri.Query, StringComparison.Ordinal);
        Assert.Contains("type=TXT", uri.Query, StringComparison.Ordinal);
    }

    [Fact]
    public void ContainsValueMatchesAQuotedTxtRecord()
    {
        string json = """{"Answer":[{"name":"_acme-challenge.example.com","type":16,"data":"\"the-value\""}]}""";

        Assert.True(DnsPropagationChecker.ContainsValue(json, "the-value"));
    }

    [Fact]
    public void ContainsValueReassemblesAChunkedTxtRecord()
    {
        string json = """{"Answer":[{"type":16,"data":"\"part1\" \"part2\""}]}""";

        Assert.True(DnsPropagationChecker.ContainsValue(json, "part1part2"));
    }

    [Fact]
    public void ContainsValueIgnoresOtherRecordTypesAndWrongValues()
    {
        string json = """{"Answer":[{"type":5,"data":"cname.example."},{"type":16,"data":"\"other\""}]}""";

        Assert.False(DnsPropagationChecker.ContainsValue(json, "the-value"));
    }

    [Fact]
    public void ContainsValueIsFalseWhenThereAreNoAnswers()
    {
        Assert.False(DnsPropagationChecker.ContainsValue("""{"Status":3}""", "x"));
    }

    [Fact]
    public async Task WaitReturnsAsSoonAsTheRecordIsVisible()
    {
        var handler = new StubDoh(_ => Answer("the-value"));
        DnsPropagationChecker checker = Checker(handler, TimeSpan.FromMinutes(2), out _);

        await checker.WaitForRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None);

        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task WaitPollsUntilTheRecordAppears()
    {
        var handler = new StubDoh(call => call < 2 ? Empty() : Answer("the-value"));
        DnsPropagationChecker checker = Checker(handler, TimeSpan.FromMinutes(2), out FakeTimeProvider time);

        await Complete(time, checker.WaitForRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None));

        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task WaitGivesUpAfterTheTimeoutAndReturns()
    {
        var handler = new StubDoh(_ => Empty());
        DnsPropagationChecker checker = Checker(handler, TimeSpan.FromSeconds(1), out _);

        await checker.WaitForRecordAsync("_acme-challenge.example.com", "the-value", CancellationToken.None);

        // One poll, then the timeout short-circuits before another sleep, so the order is not blocked.
        Assert.Equal(1, handler.Calls);
    }

    private static DnsPropagationChecker Checker(StubDoh handler, TimeSpan timeout, out FakeTimeProvider time)
    {
        time = new FakeTimeProvider(new DateTimeOffset(2026, 8, 20, 12, 0, 0, TimeSpan.Zero));
        IOptions<AutoHttpsOptions> options = Options.Create(new AutoHttpsOptions
        {
            DnsPropagationResolver = new Uri("https://doh.example/resolve"),
            DnsPropagationTimeout = timeout,
        });

        return new DnsPropagationChecker(new StubFactory(handler), options, time, NullLogger<DnsPropagationChecker>.Instance);
    }

    private static async Task Complete(FakeTimeProvider time, Task task)
    {
        for (int i = 0; i < 400 && !task.IsCompleted; i++)
        {
            await Task.Delay(5);
            time.Advance(TimeSpan.FromSeconds(10));
        }

        await task;
    }

    private static HttpResponseMessage Answer(string value) =>
        Json($$"""{"Status":0,"Answer":[{"type":16,"data":"\"{{value}}\""}]}""");

    private static HttpResponseMessage Empty() => Json("""{"Status":0,"Answer":[]}""");

    private static HttpResponseMessage Json(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/dns-json") };

    private sealed class StubFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public StubFactory(HttpMessageHandler handler) => _handler = handler;

        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    private sealed class StubDoh : HttpMessageHandler
    {
        private readonly Func<int, HttpResponseMessage> _responder;
        private int _calls;

        public StubDoh(Func<int, HttpResponseMessage> responder) => _responder = responder;

        public int Calls => Volatile.Read(ref _calls);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int call = Interlocked.Increment(ref _calls) - 1;
            return Task.FromResult(_responder(call));
        }
    }
}
