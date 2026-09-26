using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AutoHttps.Redis;

/// <summary>
/// Keeps pending <c>http-01</c> challenge answers in Redis, so any replica can answer the authority's
/// validation request rather than only the one that ordered the certificate. Each answer is a string
/// key that expires on its own if an order is interrupted before it can be removed.
/// </summary>
public sealed class RedisHttp01ChallengeStore : IHttp01ChallengeStore
{
    private readonly IConnectionMultiplexer _multiplexer;
    private readonly string _prefix;
    private readonly TimeSpan? _ttl;

    /// <summary>Initializes a new instance of the <see cref="RedisHttp01ChallengeStore"/> class.</summary>
    /// <param name="multiplexer">The Redis connection.</param>
    /// <param name="options">The key prefix and challenge lifetime.</param>
    public RedisHttp01ChallengeStore(IConnectionMultiplexer multiplexer, IOptions<RedisStoreOptions> options)
    {
        ArgumentNullException.ThrowIfNull(multiplexer);
        ArgumentNullException.ThrowIfNull(options);

        _multiplexer = multiplexer;
        _prefix = options.Value.KeyPrefix ?? string.Empty;

        // A non-positive lifetime means no expiry rather than an immediate one, which would delete the
        // answer before the authority could read it.
        TimeSpan ttl = options.Value.ChallengeTtl;
        _ttl = ttl > TimeSpan.Zero ? ttl : null;
    }

    /// <inheritdoc />
    public bool IsProcessLocal => false;

    /// <inheritdoc />
    public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        cancellationToken.ThrowIfCancellationRequested();

        return _multiplexer.GetDatabase().StringSetAsync(Key(token), keyAuthorization, _ttl);
    }

    /// <inheritdoc />
    public async Task<string?> GetAsync(string token, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        cancellationToken.ThrowIfCancellationRequested();

        RedisValue value = await _multiplexer.GetDatabase().StringGetAsync(Key(token));
        return value.IsNull ? null : value.ToString();
    }

    /// <inheritdoc />
    public Task RemoveAsync(string token, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        cancellationToken.ThrowIfCancellationRequested();

        return _multiplexer.GetDatabase().KeyDeleteAsync(Key(token));
    }

    private string Key(string token) => _prefix + "challenge:" + token;
}
