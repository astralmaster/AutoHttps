using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AutoHttps.Redis;

/// <summary>
/// Registers the Redis certificate, account key and <c>http-01</c> challenge stores, and the Redis
/// lock, with AutoHttps.
/// </summary>
public static class AutoHttpsRedisBuilderExtensions
{
    /// <summary>
    /// Keeps certificates, the ACME account key and pending <c>http-01</c> challenge answers in Redis
    /// instead of in this process and on its filesystem, and coordinates instances through a lock in
    /// the same Redis. If an <see cref="IConnectionMultiplexer"/> is already registered, it is used and
    /// <paramref name="configuration"/> is ignored.
    /// </summary>
    /// <param name="builder">The AutoHttps builder.</param>
    /// <param name="configuration">A StackExchange.Redis connection string, for example <c>localhost:6379</c>.</param>
    /// <param name="configure">Optionally configures the key prefix and the challenge lifetime.</param>
    /// <returns>The builder.</returns>
    /// <remarks>
    /// Sharing the challenge store is what lets replicas behind one DNS name pass an <c>http-01</c>
    /// validation: the authority's request lands on whichever replica the load balancer picks, and any
    /// of them can then answer it. Replace the challenge store on its own with
    /// <see cref="IAutoHttpsBuilder.UseHttp01ChallengeStore{TStore}()"/> if you want Redis for
    /// certificates but not for challenges, and the lock with
    /// <see cref="IAutoHttpsBuilder.UseDistributedLock{TLock}()"/> after this call to keep your own.
    /// </remarks>
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
            return ConnectionMultiplexer.Connect(CreateConfiguration(options.Configuration!));
        });

        builder.Services.Replace(ServiceDescriptor.Singleton<ICertificateStore, RedisCertificateStore>());
        builder.Services.Replace(ServiceDescriptor.Singleton<IAccountKeyStore, RedisAccountKeyStore>());
        builder.Services.Replace(ServiceDescriptor.Singleton<IHttp01ChallengeStore, RedisHttp01ChallengeStore>());

        // Without a shared lock every replica takes its own lock on its own disk and orders at the same
        // moment, at startup and again at every renewal, because they share the same certificate and so
        // the same renewal time.
        builder.Services.Replace(ServiceDescriptor.Singleton<IDistributedLock, RedisDistributedLock>());

        return builder;
    }

    /// <summary>
    /// StackExchange.Redis gives up at once when the server cannot be reached unless told otherwise,
    /// and the connection is made while the host builds the AutoHttps services, so Redis restarting
    /// during a deploy would stop every instance from starting at all. Reconnecting in the background
    /// is what the rest of AutoHttps expects of a store: one that cannot be reached fails an attempt,
    /// and the attempt is retried. A connection string that sets abortConnect itself is left alone.
    /// </summary>
    internal static ConfigurationOptions CreateConfiguration(string configuration)
    {
        ConfigurationOptions options = ConfigurationOptions.Parse(configuration);

        if (!configuration.Contains("abortConnect", StringComparison.OrdinalIgnoreCase))
        {
            options.AbortOnConnectFail = false;
        }

        return options;
    }
}
