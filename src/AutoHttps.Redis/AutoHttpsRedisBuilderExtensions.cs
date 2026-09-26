using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AutoHttps.Redis;

/// <summary>
/// Registers the Redis certificate, account key and <c>http-01</c> challenge stores with AutoHttps.
/// </summary>
public static class AutoHttpsRedisBuilderExtensions
{
    /// <summary>
    /// Keeps certificates, the ACME account key and pending <c>http-01</c> challenge answers in Redis
    /// instead of in this process and on its filesystem. If an <see cref="IConnectionMultiplexer"/> is
    /// already registered, it is used and <paramref name="configuration"/> is ignored.
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
    /// certificates but not for challenges.
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
            return ConnectionMultiplexer.Connect(options.Configuration!);
        });

        builder.Services.Replace(ServiceDescriptor.Singleton<ICertificateStore, RedisCertificateStore>());
        builder.Services.Replace(ServiceDescriptor.Singleton<IAccountKeyStore, RedisAccountKeyStore>());
        builder.Services.Replace(ServiceDescriptor.Singleton<IHttp01ChallengeStore, RedisHttp01ChallengeStore>());

        return builder;
    }
}
