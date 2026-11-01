using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Xunit;

namespace AutoHttps.Redis.Tests;

/// <summary>
/// The lock is what keeps replicas that share a certificate from all ordering it at the same moment,
/// which they otherwise would, because a shared certificate means a shared renewal time.
/// </summary>
[Collection(RedisCollection.Name)]
public sealed class RedisLockTests
{
    private const string Name = "app.example.com-0123456789ab";

    private readonly RedisFixture _redis;

    public RedisLockTests(RedisFixture redis) => _redis = redis;

    [Fact]
    public async Task OnlyOneInstanceHoldsTheLockAtATime()
    {
        RedisStoreOptions options = FreshOptions();
        RedisDistributedLock first = Lock(options);
        RedisDistributedLock second = Lock(options);

        IAsyncDisposable? held = await first.TryAcquireAsync(Name, CancellationToken.None);
        Assert.NotNull(held);

        Assert.Null(await second.TryAcquireAsync(Name, CancellationToken.None));

        await held!.DisposeAsync();

        IAsyncDisposable? next = await second.TryAcquireAsync(Name, CancellationToken.None);
        Assert.NotNull(next);
        await next!.DisposeAsync();
    }

    [Fact]
    public async Task DifferentCertificatesHaveDifferentLocks()
    {
        RedisStoreOptions options = FreshOptions();

        IAsyncDisposable? a = await Lock(options).TryAcquireAsync("a-name", CancellationToken.None);
        IAsyncDisposable? b = await Lock(options).TryAcquireAsync("b-name", CancellationToken.None);

        Assert.NotNull(a);
        Assert.NotNull(b);

        await a!.DisposeAsync();
        await b!.DisposeAsync();
    }

    [Fact]
    public async Task TheLeaseIsRenewedForAsLongAsTheLockIsHeld()
    {
        // An order can outlast the lease by minutes. Losing the lock halfway would let another replica
        // order the same certificate.
        RedisStoreOptions options = FreshOptions();
        options.LockLease = TimeSpan.FromSeconds(1);

        IAsyncDisposable? held = await Lock(options).TryAcquireAsync(Name, CancellationToken.None);
        Assert.NotNull(held);

        await Task.Delay(TimeSpan.FromSeconds(3));

        Assert.Null(await Lock(options).TryAcquireAsync(Name, CancellationToken.None));
        TimeSpan? ttl = await _redis.Multiplexer.GetDatabase().KeyTimeToLiveAsync(Key(options));
        Assert.NotNull(ttl);
        Assert.True(ttl!.Value <= TimeSpan.FromSeconds(1));

        await held!.DisposeAsync();
    }

    [Fact]
    public async Task AHolderThatDiesStopsBlockingTheOthersAfterOneLease()
    {
        RedisStoreOptions options = FreshOptions();
        options.LockLease = TimeSpan.FromSeconds(1);

        using (ConnectionMultiplexer doomed = await Connect())
        {
            Assert.NotNull(await new RedisDistributedLock(doomed, Options.Create(options)).TryAcquireAsync(Name, CancellationToken.None));
        }

        // The connection is gone, so nothing renews the lease or releases the lock. Until the lease runs
        // out the lock is still held, and after that another instance can take it.
        Assert.Null(await Lock(options).TryAcquireAsync(Name, CancellationToken.None));

        await Task.Delay(TimeSpan.FromSeconds(2));

        IAsyncDisposable? taken = await Lock(options).TryAcquireAsync(Name, CancellationToken.None);
        Assert.NotNull(taken);
        await taken!.DisposeAsync();
    }

    [Fact]
    public async Task AHolderWhoseLeaseRanOutCannotReleaseTheNextHoldersLock()
    {
        // A holder that stalls past its lease, for example in a long pause, comes back believing it still
        // holds the lock. Its release must not delete the lock someone else has taken since.
        RedisStoreOptions options = FreshOptions();
        options.LockLease = TimeSpan.FromSeconds(1);

        IAsyncDisposable? stale = await Lock(options).TryAcquireAsync(Name, CancellationToken.None);
        Assert.NotNull(stale);

        // Simulate the lease running out while the holder is not looking: the key is gone, and the next
        // instance takes the lock with its own token.
        await _redis.Multiplexer.GetDatabase().KeyDeleteAsync(Key(options));
        IAsyncDisposable? current = await Lock(options).TryAcquireAsync(Name, CancellationToken.None);
        Assert.NotNull(current);

        await stale!.DisposeAsync();

        Assert.Null(await Lock(options).TryAcquireAsync(Name, CancellationToken.None));
        await current!.DisposeAsync();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ALeaseLostWhileHeldIsReportedOnce(bool takenOver)
    {
        // A holder cut off from Redis for longer than its lease, or one whose key was evicted or lost in a
        // failover, no longer holds the lock, and another instance may be ordering the same certificate.
        // Carrying on silently hid that the lock had stopped doing its job.
        RedisStoreOptions options = FreshOptions();
        options.LockLease = TimeSpan.FromMilliseconds(600);
        var log = new RecordingLogger();

        IAsyncDisposable? held = await new RedisDistributedLock(_redis.Multiplexer, Options.Create(options), log)
            .TryAcquireAsync(Name, CancellationToken.None);
        Assert.NotNull(held);

        IDatabase database = _redis.Multiplexer.GetDatabase();
        if (takenOver)
        {
            await database.StringSetAsync(Key(options), "another-instance", TimeSpan.FromMinutes(1));
        }
        else
        {
            await database.KeyDeleteAsync(Key(options));
        }

        // Several renewal ticks, each a third of the lease.
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        Assert.Equal(1, log.CountOf(160));

        await held!.DisposeAsync();

        if (takenOver)
        {
            // Neither extended nor released: the key is the other instance's.
            Assert.Equal("another-instance", (string?)await database.StringGetAsync(Key(options)));
            Assert.True(await database.KeyTimeToLiveAsync(Key(options)) > TimeSpan.FromSeconds(50));
        }
    }

    [Fact]
    public async Task TheLockTheContainerBuildsReportsThroughTheApplicationsLog()
    {
        // The lock has a constructor with a logger and one without. The container has to take the first,
        // or the warning above never reaches the application's log.
        RedisStoreOptions options = FreshOptions();
        options.LockLease = TimeSpan.FromMilliseconds(600);
        var log = new RecordingLogger();

        var services = new ServiceCollection();
        services.AddSingleton<IConnectionMultiplexer>(_redis.Multiplexer);
        services.AddSingleton<ILogger<RedisDistributedLock>>(log);
        services.AddSingleton(Options.Create(options));
        services.AddSingleton<RedisDistributedLock>();
        using ServiceProvider provider = services.BuildServiceProvider();

        IAsyncDisposable? held = await provider.GetRequiredService<RedisDistributedLock>().TryAcquireAsync(Name, CancellationToken.None);
        Assert.NotNull(held);

        await _redis.Multiplexer.GetDatabase().KeyDeleteAsync(Key(options));
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        Assert.Equal(1, log.CountOf(160));
        await held!.DisposeAsync();
    }

    [Fact]
    public async Task ReleasingTheLockRemovesItsKey()
    {
        RedisStoreOptions options = FreshOptions();

        IAsyncDisposable? held = await Lock(options).TryAcquireAsync(Name, CancellationToken.None);
        Assert.True(await _redis.Multiplexer.GetDatabase().KeyExistsAsync(Key(options)));

        await held!.DisposeAsync();

        Assert.False(await _redis.Multiplexer.GetDatabase().KeyExistsAsync(Key(options)));
    }

    private RedisDistributedLock Lock(RedisStoreOptions options) => new(_redis.Multiplexer, Options.Create(options));

    private static string Key(RedisStoreOptions options) => options.KeyPrefix + "lock:" + Name;

    private static Task<ConnectionMultiplexer> Connect() =>
        ConnectionMultiplexer.ConnectAsync(
            (Environment.GetEnvironmentVariable("AUTOHTTPS_REDIS") ?? "localhost:6379") + ",abortConnect=false,connectTimeout=3000");

    // A unique prefix per test keeps them from colliding on the shared Redis.
    private static RedisStoreOptions FreshOptions() =>
        new() { KeyPrefix = "autohttps-test:" + Guid.NewGuid().ToString("n") + ":" };

    private sealed class RecordingLogger : ILogger<RedisDistributedLock>
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<int> _events = new();

        public int CountOf(int eventId) => _events.Count(id => id == eventId);

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            _events.Enqueue(eventId.Id);
    }
}
