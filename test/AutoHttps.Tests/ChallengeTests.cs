using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Challenges;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public class InMemoryHttp01ChallengeStoreTests
{
    [Fact]
    public async Task ATokenIsFoundOnlyWhileItIsPending()
    {
        var store = new InMemoryHttp01ChallengeStore();

        Assert.Null(await store.GetAsync("token", CancellationToken.None));

        await store.AddAsync("token", "token.thumbprint", CancellationToken.None);
        Assert.Equal("token.thumbprint", await store.GetAsync("token", CancellationToken.None));

        await store.RemoveAsync("token", CancellationToken.None);
        Assert.Null(await store.GetAsync("token", CancellationToken.None));
    }

    [Fact]
    public async Task RemovingAnUnknownTokenIsHarmless()
    {
        var store = new InMemoryHttp01ChallengeStore();
        await store.RemoveAsync("never-added", CancellationToken.None);

        Assert.Equal(0, store.Count);
    }

    [Fact]
    public async Task SeveralChallengesCanBePendingAtOnce()
    {
        var store = new InMemoryHttp01ChallengeStore();

        await store.AddAsync("a", "a.key", CancellationToken.None);
        await store.AddAsync("b", "b.key", CancellationToken.None);

        Assert.Equal(2, store.Count);
        Assert.Equal("a.key", await store.GetAsync("a", CancellationToken.None));
        Assert.Equal("b.key", await store.GetAsync("b", CancellationToken.None));
    }

    [Fact]
    public async Task PublishingTheSameTokenTwiceKeepsTheLatestAnswer()
    {
        var store = new InMemoryHttp01ChallengeStore();

        await store.AddAsync("token", "first", CancellationToken.None);
        await store.AddAsync("token", "second", CancellationToken.None);

        Assert.Equal("second", await store.GetAsync("token", CancellationToken.None));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public async Task TokensAreMatchedExactly()
    {
        var store = new InMemoryHttp01ChallengeStore();
        await store.AddAsync("Token", "value", CancellationToken.None);

        Assert.Null(await store.GetAsync("token", CancellationToken.None));
    }

    [Fact]
    public void TheDefaultStoreIsPrivateToThisProcess() =>
        Assert.True(new InMemoryHttp01ChallengeStore().IsProcessLocal);
}

public class Http01ChallengeMiddlewareTests
{
    [Fact]
    public async Task APendingTokenIsAnsweredWithItsKeyAuthorization()
    {
        var store = new InMemoryHttp01ChallengeStore();
        await store.AddAsync("the-token", "the-token.the-thumbprint", CancellationToken.None);

        HttpContext context = CreateContext("/.well-known/acme-challenge/the-token");
        await CreateMiddleware(store, out bool[] nextCalled, out Http01RequestProbe probe).InvokeAsync(context);

        Assert.False(nextCalled[0]);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal("the-token.the-thumbprint", ReadBody(context));
        Assert.True(probe.WasServed("the-token"));
    }

    [Fact]
    public async Task AnUnknownTokenFallsThroughToTheApplication()
    {
        HttpContext context = CreateContext("/.well-known/acme-challenge/unknown");
        await CreateMiddleware(new InMemoryHttp01ChallengeStore(), out bool[] nextCalled, out Http01RequestProbe probe)
            .InvokeAsync(context);

        Assert.True(nextCalled[0]);
        Assert.False(probe.WasServed("unknown"));
    }

    [Fact]
    public async Task RequestsOutsideTheChallengePathAreUntouched()
    {
        var store = new InMemoryHttp01ChallengeStore();
        await store.AddAsync("the-token", "value", CancellationToken.None);

        HttpContext context = CreateContext("/index.html");
        await CreateMiddleware(store, out bool[] nextCalled, out _).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    [Fact]
    public async Task ANestedPathIsNotTreatedAsAToken()
    {
        var store = new InMemoryHttp01ChallengeStore();
        await store.AddAsync("the-token", "value", CancellationToken.None);

        HttpContext context = CreateContext("/.well-known/acme-challenge/the-token/extra");
        await CreateMiddleware(store, out bool[] nextCalled, out _).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    [Fact]
    public async Task AnEmptyTokenFallsThrough()
    {
        HttpContext context = CreateContext("/.well-known/acme-challenge/");
        await CreateMiddleware(new InMemoryHttp01ChallengeStore(), out bool[] nextCalled, out _).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    [Fact]
    public async Task TheResponseIsSentAsOpaqueBytesWithAnExactLength()
    {
        var store = new InMemoryHttp01ChallengeStore();
        await store.AddAsync("t", "t.thumb", CancellationToken.None);

        HttpContext context = CreateContext("/.well-known/acme-challenge/t");
        await CreateMiddleware(store, out _, out _).InvokeAsync(context);

        Assert.Equal("application/octet-stream", context.Response.ContentType);
        Assert.Equal(7, context.Response.ContentLength);
    }

    [Fact]
    public async Task TokenMatchingIsCaseSensitive()
    {
        var store = new InMemoryHttp01ChallengeStore();
        await store.AddAsync("Token", "value", CancellationToken.None);

        HttpContext context = CreateContext("/.well-known/acme-challenge/token");
        await CreateMiddleware(store, out bool[] nextCalled, out _).InvokeAsync(context);

        Assert.True(nextCalled[0]);
    }

    [Fact]
    public async Task AStoreThatCannotBeReachedFallsThroughAndIsReported()
    {
        // A shared store that is down must not surface as a 500 with nothing to explain it. The
        // authority sees an unanswered challenge either way; the log is what says why.
        var logger = new CapturingLogger();
        var middleware = new Http01ChallengeMiddleware(
            _ => Task.CompletedTask,
            new UnreachableStore(),
            new Http01RequestProbe(),
            logger);

        HttpContext context = CreateContext("/.well-known/acme-challenge/the-token");
        await middleware.InvokeAsync(context);

        Assert.Equal(1, logger.CountOf(143));
        Assert.NotEqual(StatusCodes.Status500InternalServerError, context.Response.StatusCode);
    }

    private static Http01ChallengeMiddleware CreateMiddleware(
        IHttp01ChallengeStore store,
        out bool[] nextCalled,
        out Http01RequestProbe probe)
    {
        bool[] called = [false];
        nextCalled = called;
        probe = new Http01RequestProbe();

        return new Http01ChallengeMiddleware(
            _ =>
            {
                called[0] = true;
                return Task.CompletedTask;
            },
            store,
            probe,
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

    private sealed class UnreachableStore : IHttp01ChallengeStore
    {
        public bool IsProcessLocal => false;

        public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the store is down");

        public Task<string?> GetAsync(string token, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the store is down");

        public Task RemoveAsync(string token, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the store is down");
    }

    private sealed class CapturingLogger : ILogger<Http01ChallengeMiddleware>
    {
        private readonly ConcurrentDictionary<int, int> _counts = new();

        public int CountOf(int eventId) => _counts.TryGetValue(eventId, out int count) ? count : 0;

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            _counts.AddOrUpdate(eventId.Id, 1, static (_, existing) => existing + 1);
    }
}

public class Http01ChallengeHandlerTests
{
    private static readonly ChallengeContext Context = new("dns", "app.example.com", "the-token", "the-token.thumb", "ignored");

    [Fact]
    public void BothDnsAndIpIdentifiersCanBeValidatedOverHttp()
    {
        Http01ChallengeHandler handler = CreateHandler(new InMemoryHttp01ChallengeStore(), out _);

        Assert.True(handler.CanHandle("dns"));
        Assert.True(handler.CanHandle("ip"));
    }

    [Fact]
    public async Task PreparePublishesTheAnswerAndCleanupRemovesIt()
    {
        var store = new InMemoryHttp01ChallengeStore();
        Http01ChallengeHandler handler = CreateHandler(store, out _);

        await handler.PrepareAsync(Context, CancellationToken.None);
        Assert.Equal("the-token.thumb", await store.GetAsync("the-token", CancellationToken.None));

        await handler.CleanupAsync(Context, CancellationToken.None);
        Assert.Null(await store.GetAsync("the-token", CancellationToken.None));
    }

    [Fact]
    public async Task CleanupForgetsThatThisProcessServedTheToken()
    {
        var store = new InMemoryHttp01ChallengeStore();
        Http01ChallengeHandler handler = CreateHandler(store, out Http01RequestProbe probe);

        probe.MarkServed("the-token");
        await handler.CleanupAsync(Context, CancellationToken.None);

        Assert.False(probe.WasServed("the-token"));
    }

    [Fact]
    public async Task CleanupForgetsTheTokenEvenWhenTheStoreCannotBeReached()
    {
        // The caller catches and logs a cleanup failure, so without the unconditional forget a store
        // that keeps throwing would leave an entry behind on every attempt.
        var probe = new Http01RequestProbe();
        var handler = new Http01ChallengeHandler(new ThrowingStore(), probe);
        probe.MarkServed("the-token");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => handler.CleanupAsync(Context, CancellationToken.None));

        Assert.False(probe.WasServed("the-token"));
    }

    [Fact]
    public void AChallengeThisProcessAnsweredAddsNothingToTheAuthoritysReport()
    {
        Http01ChallengeHandler handler = CreateHandler(new InMemoryHttp01ChallengeStore(), out Http01RequestProbe probe);
        probe.MarkServed("the-token");

        Assert.Null(handler.DescribeFailure(Context, Failure(AcmeErrorTypes.Unauthorized)));
    }

    [Fact]
    public void WithAProcessLocalStoreAnUnansweredChallengeNamesSomethingInFront()
    {
        Http01ChallengeHandler handler = CreateHandler(new InMemoryHttp01ChallengeStore(), out _);

        string? explanation = handler.DescribeFailure(Context, Failure(AcmeErrorTypes.Unauthorized));

        Assert.NotNull(explanation);
        Assert.Contains("in front of the application", explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void WithASharedStoreAnUnansweredChallengeDoesNotBlameAProxy()
    {
        // Another replica may legitimately have answered it, so the interception conclusion would be
        // wrong. What is worth checking instead is that every replica reads the same store.
        Http01ChallengeHandler handler = CreateHandler(new SharedStore(), out _);

        string? explanation = handler.DescribeFailure(Context, Failure(AcmeErrorTypes.Unauthorized));

        Assert.NotNull(explanation);
        Assert.Contains("same challenge store", explanation, StringComparison.Ordinal);
        Assert.DoesNotContain("something in front of the application answered", explanation, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TheAuthoritysOwnDnsVerdictReadsTheSameWhicheverStoreIsUsed(bool processLocal)
    {
        Http01ChallengeHandler handler = CreateHandler(Store(processLocal), out _);

        string? explanation = handler.DescribeFailure(Context, Failure(AcmeErrorTypes.Dns));

        Assert.NotNull(explanation);
        Assert.Contains("could not resolve the name", explanation, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AConnectionFailureStillPointsAtPort80(bool processLocal)
    {
        Http01ChallengeHandler handler = CreateHandler(Store(processLocal), out _);

        string? explanation = handler.DescribeFailure(Context, Failure(AcmeErrorTypes.Connection));

        Assert.NotNull(explanation);
        Assert.Contains("port 80", explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnrecognisedFailureMentionsTheSharedStoreOnlyWhenThereIsOne()
    {
        Assert.DoesNotContain(
            "shared",
            CreateHandler(new InMemoryHttp01ChallengeStore(), out _).DescribeFailure(Context, Failure("urn:example:other"))!,
            StringComparison.Ordinal);

        Assert.Contains(
            "shared",
            CreateHandler(new SharedStore(), out _).DescribeFailure(Context, Failure("urn:example:other"))!,
            StringComparison.Ordinal);
    }

    private static IHttp01ChallengeStore Store(bool processLocal) =>
        processLocal ? new InMemoryHttp01ChallengeStore() : new SharedStore();

    private static Http01ChallengeHandler CreateHandler(IHttp01ChallengeStore store, out Http01RequestProbe probe)
    {
        probe = new Http01RequestProbe();
        return new Http01ChallengeHandler(store, probe);
    }

    private static AcmeException Failure(string errorType) =>
        new("the authority rejected the challenge", errorType, "detail", 403);

    private sealed class ThrowingStore : IHttp01ChallengeStore
    {
        public bool IsProcessLocal => false;

        public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the store is down");

        public Task<string?> GetAsync(string token, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the store is down");

        public Task RemoveAsync(string token, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the store is down");
    }

    private sealed class SharedStore : IHttp01ChallengeStore
    {
        private readonly ConcurrentDictionary<string, string> _pending = new(StringComparer.Ordinal);

        public bool IsProcessLocal => false;

        public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken)
        {
            _pending[token] = keyAuthorization;
            return Task.CompletedTask;
        }

        public Task<string?> GetAsync(string token, CancellationToken cancellationToken) =>
            Task.FromResult(_pending.TryGetValue(token, out string? value) ? value : null);

        public Task RemoveAsync(string token, CancellationToken cancellationToken)
        {
            _pending.TryRemove(token, out _);
            return Task.CompletedTask;
        }
    }
}

public class Http01ChallengeStoreRegistrationTests
{
    [Fact]
    public void TheInMemoryStoreIsRegisteredByDefault()
    {
        var services = new ServiceCollection();
        services.AddAutoHttps(Configure);

        Assert.Equal(typeof(InMemoryHttp01ChallengeStore), Registered(services).ImplementationType);
    }

    [Fact]
    public void ReplacingTheStoreLeavesExactlyOneRegistration()
    {
        // Replace rather than add, so the middleware and the handler cannot end up on different stores.
        var services = new ServiceCollection();
        services.AddAutoHttps(Configure).UseHttp01ChallengeStore<FakeStore>();

        Assert.Equal(typeof(FakeStore), Registered(services).ImplementationType);
    }

    private static ServiceDescriptor Registered(IServiceCollection services) =>
        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IHttp01ChallengeStore));

    private static void Configure(AutoHttpsOptions options)
    {
        options.DomainNames.Add("app.example.com");
        options.EmailAddress = "operator@example.com";
        options.AcceptTermsOfService = true;
    }

    private sealed class FakeStore : IHttp01ChallengeStore
    {
        public bool IsProcessLocal => false;

        public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> GetAsync(string token, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task RemoveAsync(string token, CancellationToken cancellationToken) => Task.CompletedTask;
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
