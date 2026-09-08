using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AutoHttps.Redis;

/// <summary>
/// Registers the Redis certificate and account key stores with AutoHttps.
/// </summary>
public static class AutoHttpsRedisBuilderExtensions
{
    /// <summary>
    /// Keeps certificates and the ACME account key in Redis instead of on the filesystem. If an
    /// <see cref="IConnectionMultiplexer"/> is already registered, it is used and
    /// <paramref name="configuration"/> is ignored.
    /// </summary>
    /// <param name="builder">The AutoHttps builder.</param>
    /// <param name="configuration">A StackExchange.Redis connection string, for example <c>localhost:6379</c>.</param>
    /// <param name="configure">Optionally configures the key prefix.</param>
    /// <returns>The builder.</returns>
    public static IAutoHttpsBuilder UseRedis(
        this IAutoHttpsBuilder builder,
        string configuration,
        Action<RedisStoreOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(configuration);

        builder.Services.Configure<RedisStoreOptions>(options =>
        {
            options.Configuration = configuration;
            configure?.Invoke(options);
        });

        builder.Services.TryAddSingleton<IConnectionMultiplexer>(provider =>
        {
            RedisStoreOptions options = provider.GetRequiredService<IOptions<RedisStoreOptions>>().Value;
            return ConnectionMultiplexer.Connect(options.Configuration!);
        });

        builder.Services.Replace(ServiceDescriptor.Singleton<ICertificateStore, RedisCertificateStore>());
        builder.Services.Replace(ServiceDescriptor.Singleton<IAccountKeyStore, RedisAccountKeyStore>());

        return builder;
    }
}
