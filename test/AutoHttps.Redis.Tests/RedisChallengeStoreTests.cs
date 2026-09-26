using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Xunit;

namespace AutoHttps.Redis.Tests;

[Collection(RedisCollection.Name)]
public sealed class RedisChallengeStoreTests
{
    private const string Token = "the-token";
    private const string KeyAuthorization = "the-token.the-thumbprint";

    private readonly RedisFixture _redis;

    public RedisChallengeStoreTests(RedisFixture redis) => _redis = redis;

    [Fact]
    public async Task APublishedAnswerCanBeReadBack()
    {
        RedisHttp01ChallengeStore store = Store(FreshOptions());

        await store.AddAsync(Token, KeyAuthorization, CancellationToken.None);

        Assert.Equal(KeyAuthorization, await store.GetAsync(Token, CancellationToken.None));
    }

    [Fact]
    public async Task AnUnknownTokenReturnsNull() =>
        Assert.Null(await Store(FreshOptions()).GetAsync("never-published", CancellationToken.None));

    [Fact]
    public async Task RemovingAnAnswerMakesItUnreadable()
    {
        RedisHttp01ChallengeStore store = Store(FreshOptions());
        await store.AddAsync(Token, KeyAuthorization, CancellationToken.None);

        await store.RemoveAsync(Token, CancellationToken.None);

        Assert.Null(await store.GetAsync(Token, CancellationToken.None));
    }

    [Fact]
    public async Task RemovingAnUnknownTokenIsHarmless() =>
        await Store(FreshOptions()).RemoveAsync("never-published", CancellationToken.None);

    [Fact]
    public async Task PublishingTheSameTokenTwiceKeepsTheLatestAnswer()
    {
        RedisHttp01ChallengeStore store = Store(FreshOptions());

        await store.AddAsync(Token, "first", CancellationToken.None);
        await store.AddAsync(Token, "second", CancellationToken.None);

        Assert.Equal("second", await store.GetAsync(Token, CancellationToken.None));
    }

    [Fact]
    public async Task AnAnswerPublishedByOneInstanceIsReadableByAnother()
    {
        // The whole point of the store: the replica that orders and the replica the authority reaches
        // are different objects holding no shared memory, only the same Redis keys.
        RedisStoreOptions options = FreshOptions();
        RedisHttp01ChallengeStore orderer = Store(options);
        RedisHttp01ChallengeStore responder = Store(options);

        await orderer.AddAsync(Token, KeyAuthorization, CancellationToken.None);

        Assert.Equal(KeyAuthorization, await responder.GetAsync(Token, CancellationToken.None));

        await orderer.RemoveAsync(Token, CancellationToken.None);

        Assert.Null(await responder.GetAsync(Token, CancellationToken.None));
    }

    [Fact]
    public void TheStoreReportsItselfAsShared() =>
        Assert.False(Store(FreshOptions()).IsProcessLocal);

    [Fact]
    public async Task AnAnswerCarriesTheConfiguredLifetime()
    {
        RedisStoreOptions options = FreshOptions();
        options.ChallengeTtl = TimeSpan.FromMinutes(15);

        await Store(options).AddAsync(Token, KeyAuthorization, CancellationToken.None);

        TimeSpan? ttl = await _redis.Multiplexer.GetDatabase().KeyTimeToLiveAsync(options.KeyPrefix + "challenge:" + Token);

        Assert.NotNull(ttl);
        Assert.InRange(ttl!.Value, TimeSpan.FromMinutes(14), TimeSpan.FromMinutes(15));
    }

    [Fact]
    public async Task ANonPositiveLifetimeKeepsTheAnswerUntilItIsRemoved()
    {
        // Zero must not mean "expire immediately", which would delete the answer before the authority
        // could read it.
        RedisStoreOptions options = FreshOptions();
        options.ChallengeTtl = TimeSpan.Zero;

        RedisHttp01ChallengeStore store = Store(options);
        await store.AddAsync(Token, KeyAuthorization, CancellationToken.None);

        TimeSpan? ttl = await _redis.Multiplexer.GetDatabase().KeyTimeToLiveAsync(options.KeyPrefix + "challenge:" + Token);

        Assert.Null(ttl);
        Assert.Equal(KeyAuthorization, await store.GetAsync(Token, CancellationToken.None));
    }

    [Fact]
    public async Task AnAnswerLeftBehindByAnInterruptedOrderExpiresOnItsOwn()
    {
        RedisStoreOptions options = FreshOptions();
        options.ChallengeTtl = TimeSpan.FromSeconds(1);

        RedisHttp01ChallengeStore store = Store(options);
        await store.AddAsync(Token, KeyAuthorization, CancellationToken.None);

        Assert.Equal(KeyAuthorization, await store.GetAsync(Token, CancellationToken.None));

        await Task.Delay(TimeSpan.FromSeconds(2));

        Assert.Null(await store.GetAsync(Token, CancellationToken.None));
    }

    [Fact]
    public async Task TwoDomainsBeingValidatedAtOnceDoNotCollide()
    {
        RedisHttp01ChallengeStore store = Store(FreshOptions());

        await store.AddAsync("token-a", "a.thumb", CancellationToken.None);
        await store.AddAsync("token-b", "b.thumb", CancellationToken.None);

        Assert.Equal("a.thumb", await store.GetAsync("token-a", CancellationToken.None));
        Assert.Equal("b.thumb", await store.GetAsync("token-b", CancellationToken.None));

        await store.RemoveAsync("token-a", CancellationToken.None);

        Assert.Null(await store.GetAsync("token-a", CancellationToken.None));
        Assert.Equal("b.thumb", await store.GetAsync("token-b", CancellationToken.None));
    }

    private RedisHttp01ChallengeStore Store(RedisStoreOptions options) =>
        new(_redis.Multiplexer, Options.Create(options));

    // A unique prefix per test keeps them from colliding on the shared Redis.
    private static RedisStoreOptions FreshOptions() =>
        new() { KeyPrefix = "autohttps-test:" + Guid.NewGuid().ToString("n") + ":" };
}
