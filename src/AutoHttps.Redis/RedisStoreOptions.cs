namespace AutoHttps.Redis;

/// <summary>
/// Configures the Redis certificate and account key stores.
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
}
