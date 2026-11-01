using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AutoHttps.Redis;

/// <summary>
/// Stops several instances sharing one Redis from ordering the same certificate at once. The lock is a
/// key holding a random token, set only if absent and given a lease that is renewed while the order
/// runs, so an instance that dies holding it blocks the others for one lease at most.
/// </summary>
public sealed class RedisDistributedLock : IDistributedLock
{
    // Both only act while the key still holds this holder's token. A holder whose lease ran out, for
    // example after a long pause, must neither extend nor delete a lock another instance now holds.
    private const string RenewScript =
        "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end";

    private const string ReleaseScript =
        "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";

    private readonly IConnectionMultiplexer _multiplexer;
    private readonly ILogger _logger;
    private readonly string _prefix;
    private readonly TimeSpan _lease;

    /// <summary>Initializes a new instance of the <see cref="RedisDistributedLock"/> class.</summary>
    /// <param name="multiplexer">The Redis connection.</param>
    /// <param name="options">The key prefix and the lease.</param>
    public RedisDistributedLock(IConnectionMultiplexer multiplexer, IOptions<RedisStoreOptions> options)
        : this(multiplexer, options, NullLogger<RedisDistributedLock>.Instance)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="RedisDistributedLock"/> class.</summary>
    /// <param name="multiplexer">The Redis connection.</param>
    /// <param name="options">The key prefix and the lease.</param>
    /// <param name="logger">Receives a warning when a held lock's lease is lost.</param>
    public RedisDistributedLock(
        IConnectionMultiplexer multiplexer,
        IOptions<RedisStoreOptions> options,
        ILogger<RedisDistributedLock> logger)
    {
        ArgumentNullException.ThrowIfNull(multiplexer);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _multiplexer = multiplexer;
        _logger = logger;
        _prefix = options.Value.KeyPrefix ?? string.Empty;

        TimeSpan lease = options.Value.LockLease;
        _lease = lease > TimeSpan.Zero ? lease : RedisStoreOptions.DefaultLockLease;
    }

    /// <inheritdoc />
    public async Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        cancellationToken.ThrowIfCancellationRequested();

        IDatabase database = _multiplexer.GetDatabase();
        RedisKey key = _prefix + "lock:" + name;
        RedisValue token = Guid.NewGuid().ToString("n");

        bool taken = await database.StringSetAsync(key, token, _lease, When.NotExists);
        return taken ? new Lease(database, key, token, _lease, _logger) : null;
    }

    private sealed class Lease : IAsyncDisposable
    {
        private readonly IDatabase _database;
        private readonly RedisKey _key;
        private readonly RedisValue _token;
        private readonly ILogger _logger;
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _renewal;

        public Lease(IDatabase database, RedisKey key, RedisValue token, TimeSpan lease, ILogger logger)
        {
            _database = database;
            _key = key;
            _token = token;
            _logger = logger;
            _renewal = RenewAsync(lease);
        }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            await _renewal;
            _stop.Dispose();

            try
            {
                await _database.ScriptEvaluateAsync(ReleaseScript, [_key], [_token]);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Redis is unreachable. The lease runs out on its own, which is the case it exists for.
            }
        }

        // An order can take minutes, waiting on DNS propagation and the authority's validation, which
        // is longer than a lease short enough to recover quickly from a crashed holder.
        private async Task RenewAsync(TimeSpan lease)
        {
            using var timer = new PeriodicTimer(lease / 3);
            RedisValue milliseconds = (long)lease.TotalMilliseconds;

            try
            {
                while (await timer.WaitForNextTickAsync(_stop.Token))
                {
                    RedisResult renewed;
                    try
                    {
                        renewed = await _database.ScriptEvaluateAsync(RenewScript, [_key], [_token, milliseconds]);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        // A brief outage: the remaining lease covers it, and the next tick tries again.
                        continue;
                    }

                    // Zero means the key no longer holds this holder's token: the lease ran out during an
                    // outage, or the key was evicted or lost in a failover, and another instance may hold
                    // the lock now. Renewing cannot win it back, and saying so once is what matters.
                    if ((long)renewed == 0)
                    {
                        RedisLog.LockLeaseLost(_logger, _key.ToString(), lease);
                        return;
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
        }
    }
}
