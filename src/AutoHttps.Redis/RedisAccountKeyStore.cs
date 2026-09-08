using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AutoHttps.Redis;

/// <summary>
/// Stores the ACME account key in Redis, so instances that do not share a filesystem keep one shared
/// registration with the certificate authority.
/// </summary>
public sealed class RedisAccountKeyStore : IAccountKeyStore
{
    private readonly IConnectionMultiplexer _multiplexer;
    private readonly string _prefix;

    /// <summary>Initializes a new instance of the <see cref="RedisAccountKeyStore"/> class.</summary>
    public RedisAccountKeyStore(IConnectionMultiplexer multiplexer, IOptions<RedisStoreOptions> options)
    {
        ArgumentNullException.ThrowIfNull(multiplexer);
        ArgumentNullException.ThrowIfNull(options);

        _multiplexer = multiplexer;
        _prefix = options.Value.KeyPrefix ?? string.Empty;
    }

    /// <inheritdoc />
    public async Task<string?> LoadAsync(string name, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        RedisValue value = await _multiplexer.GetDatabase().StringGetAsync(Key(name));
        return value.IsNullOrEmpty ? null : value.ToString();
    }

    /// <inheritdoc />
    public Task SaveAsync(string name, string privateKeyPem, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return _multiplexer.GetDatabase().StringSetAsync(Key(name), privateKeyPem);
    }

    private string Key(string name) => _prefix + "account:" + name;
}
