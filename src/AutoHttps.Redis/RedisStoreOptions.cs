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
}
