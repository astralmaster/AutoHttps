using System;

namespace AutoHttps.Redis;

/// <summary>
/// Configures the Redis certificate, account key and challenge stores.
/// </summary>
public sealed class RedisStoreOptions
{
    /// <summary>
    /// The StackExchange.Redis connection string, for example <c>localhost:6379</c>. Ignored when an
    /// <see cref="StackExchange.Redis.IConnectionMultiplexer"/> is already registered in the container.
    /// </summary>
    public string? Configuration { get; set; }

    /// <summary>
    /// A prefix for every key AutoHttps writes, so its data is easy to see and does not collide with
    /// other users of the same Redis. Defaults to <c>autohttps:</c>.
    /// </summary>
    public string KeyPrefix { get; set; } = "autohttps:";

    /// <summary>
    /// How long a published <c>http-01</c> challenge answer is kept. AutoHttps removes each answer once
    /// the challenge is finished, so this only bounds what an order interrupted partway can leave
    /// behind. Defaults to 15 minutes, comfortably longer than
    /// <see cref="AutoHttpsOptions.ValidationTimeout"/>. Set it to zero or less to keep answers until
    /// they are removed.
    /// </summary>
    public TimeSpan ChallengeTtl { get; set; } = TimeSpan.FromMinutes(15);

    internal static readonly TimeSpan DefaultLockLease = TimeSpan.FromMinutes(1);

    /// <summary>
    /// How long the lock that stops instances ordering at once survives without being renewed. The
    /// holder renews it every third of this while its order runs, so it only bounds how long an
    /// instance that died holding the lock keeps the others waiting. Defaults to 1 minute.
    /// </summary>
    public TimeSpan LockLease { get; set; } = DefaultLockLease;
}
