using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Challenges;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public class Http01ChallengeStoreTests
{
    [Fact]
    public void ATokenIsFoundOnlyWhileItIsPending()
    {
        var store = new Http01ChallengeStore();

        Assert.False(store.TryGet("token", out _));

        store.Add("token", "token.thumbprint");
        Assert.True(store.TryGet("token", out string? keyAuthorization));
        Assert.Equal("token.thumbprint", keyAuthorization);

        store.Remove("token");
        Assert.False(store.TryGet("token", out _));
    }

    [Fact]
    public void RemovingAnUnknownTokenIsHarmless()
    {
        var store = new Http01ChallengeStore();
        store.Remove("never-added");

        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void SeveralChallengesCanBePendingAtOnce()
    {
        var store = new Http01ChallengeStore();

        store.Add("a", "a.key");
        store.Add("b", "b.key");

        Assert.Equal(2, store.Count);
        Assert.True(store.TryGet("a", out _));
        Assert.True(store.TryGet("b", out _));
    }
}

public class Http01ChallengeMiddlewareTests
{
    [Fact]
    public async Task APendingTokenIsAnsweredWithItsKeyAuthorization()
    {
        var store = new Http01ChallengeStore();
        store.Add("the-token", "the-token.the-thumbprint");

        HttpContext context = CreateContext("/.well-known/acme-challenge/the-token");
        await CreateMiddleware(store, out bool[] nextCalled).InvokeAsync(context);

        Assert.False(nextCalled[0]);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal("the-token.the-thumbprint", ReadBody(context));
    }

    [Fact]
    public async Task AnUnknownTokenFallsThroughToTheApplication()
    {
        HttpContext context = CreateContext("/.well-known/acme-challenge/unknown");
        await CreateMiddleware(new Http01ChallengeStore(), out bool[] nextCalled).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    [Fact]
    public async Task RequestsOutsideTheChallengePathAreUntouched()
    {
        var store = new Http01ChallengeStore();
        store.Add("the-token", "value");

        HttpContext context = CreateContext("/index.html");
        await CreateMiddleware(store, out bool[] nextCalled).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    [Fact]
    public async Task ANestedPathIsNotTreatedAsAToken()
    {
        var store = new Http01ChallengeStore();
        store.Add("the-token", "value");

        HttpContext context = CreateContext("/.well-known/acme-challenge/the-token/extra");
        await CreateMiddleware(store, out bool[] nextCalled).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    [Fact]
    public async Task AnEmptyTokenFallsThrough()
    {
        HttpContext context = CreateContext("/.well-known/acme-challenge/");
        await CreateMiddleware(new Http01ChallengeStore(), out bool[] nextCalled).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    [Fact]
    public async Task TheResponseIsSentAsOpaqueBytesWithAnExactLength()
    {
        var store = new Http01ChallengeStore();
        store.Add("t", "t.thumb");

        HttpContext context = CreateContext("/.well-known/acme-challenge/t");
        await CreateMiddleware(store, out _).InvokeAsync(context);

        Assert.Equal("application/octet-stream", context.Response.ContentType);
        Assert.Equal(7, context.Response.ContentLength);
    }

    [Fact]
    public async Task TokenMatchingIsCaseSensitive()
    {
        var store = new Http01ChallengeStore();
        store.Add("Token", "value");

        HttpContext context = CreateContext("/.well-known/acme-challenge/token");
        await CreateMiddleware(store, out bool[] nextCalled).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    private static Http01ChallengeMiddleware CreateMiddleware(Http01ChallengeStore store, out bool[] nextCalled)
    {
        bool[] called = [false];
        nextCalled = called;

        return new Http01ChallengeMiddleware(
            _ =>
            {
                called[0] = true;
                return Task.CompletedTask;
            },
            store,
            NullLogger<Http01ChallengeMiddleware>.Instance);
    }

    private static HttpContext CreateContext(string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();

        return context;
    }

    private static string ReadBody(HttpContext context)
    {
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, Encoding.ASCII);

        return reader.ReadToEnd();
    }
}

public class Dns01ChallengeHandlerTests
{
    [Theory]
    [InlineData("example.com", "_acme-challenge.example.com")]
    [InlineData("www.example.com", "_acme-challenge.www.example.com")]
    [InlineData("*.example.com", "_acme-challenge.example.com")]
    public void TheRecordNameIsDerivedFromTheIdentifierWithoutTheWildcardLabel(string identifier, string expected) =>
        Assert.Equal(expected, Dns01ChallengeHandler.GetRecordName(identifier));

    [Fact]
    public void TheHandlerIsInertWithoutAProvider()
    {
        var handler = new Dns01ChallengeHandler(null, TimeSpan.Zero, TimeProvider.System);

        Assert.False(handler.CanHandle("dns"));
    }

    [Fact]
    public void OnlyDnsIdentifiersCanBeValidatedByDns()
    {
        var handler = new Dns01ChallengeHandler(new RecordingProvider(), TimeSpan.Zero, TimeProvider.System);

        Assert.True(handler.CanHandle("dns"));
        Assert.False(handler.CanHandle("ip"));
    }

    [Fact]
    public async Task PrepareCreatesTheRecordAndCleanupRemovesTheSameOne()
    {
        var provider = new RecordingProvider();
        var handler = new Dns01ChallengeHandler(provider, TimeSpan.Zero, TimeProvider.System);
        var context = new ChallengeContext("dns", "*.example.com", "token", "token.thumb", "digest-value");

        await handler.PrepareAsync(context, CancellationToken.None);
        await handler.CleanupAsync(context, CancellationToken.None);

        Assert.Equal([("create", "_acme-challenge.example.com", "digest-value")], provider.Calls.ToArray()[..1]);
        Assert.Equal([("delete", "_acme-challenge.example.com", "digest-value")], provider.Calls.ToArray()[1..]);
    }

    [Fact]
    public async Task PrepareWaitsForTheConfiguredPropagationDelay()
    {
        var time = new FakeTimeProvider();
        var handler = new Dns01ChallengeHandler(new RecordingProvider(), TimeSpan.FromSeconds(30), time);
        var context = new ChallengeContext("dns", "example.com", "token", "token.thumb", "digest");

        Task prepare = handler.PrepareAsync(context, CancellationToken.None);

        Assert.False(prepare.IsCompleted);
        time.Advance(TimeSpan.FromSeconds(30));
        await prepare;
    }

    [Fact]
    public async Task TheDelegateProviderForwardsToItsCallbacks()
    {
        var created = new List<string>();
        var deleted = new List<string>();

        var provider = new DelegateDnsChallengeProvider(
            (name, value, _) =>
            {
                created.Add($"{name}={value}");
                return Task.CompletedTask;
            },
            (name, value, _) =>
            {
                deleted.Add($"{name}={value}");
                return Task.CompletedTask;
            });

        await provider.CreateTxtRecordAsync("_acme-challenge.example.com", "abc", CancellationToken.None);
        await provider.DeleteTxtRecordAsync("_acme-challenge.example.com", "abc", CancellationToken.None);

        Assert.Equal(["_acme-challenge.example.com=abc"], created);
        Assert.Equal(["_acme-challenge.example.com=abc"], deleted);
    }

    [Fact]
    public void TheDelegateProviderRejectsMissingCallbacks()
    {
        Assert.Throws<ArgumentNullException>(() => new DelegateDnsChallengeProvider(null!, (_, _, _) => Task.CompletedTask));
        Assert.Throws<ArgumentNullException>(() => new DelegateDnsChallengeProvider((_, _, _) => Task.CompletedTask, null!));
    }

    private sealed class RecordingProvider : IDnsChallengeProvider
    {
        public List<(string Operation, string Name, string Value)> Calls { get; } = [];

        public Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
        {
            Calls.Add(("create", recordName, recordValue));
            return Task.CompletedTask;
        }

        public Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
        {
            Calls.Add(("delete", recordName, recordValue));
            return Task.CompletedTask;
        }
    }
}
