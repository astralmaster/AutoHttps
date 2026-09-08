using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AutoHttps.Redis;

/// <summary>
/// Stores issued certificates in Redis, so instances that do not share a filesystem can still share
/// certificates. Each certificate is a hash with the chain and the private key.
/// </summary>
public sealed class RedisCertificateStore : ICertificateStore
{
    private const string ChainField = "chain";
    private const string KeyField = "key";

    private readonly IConnectionMultiplexer _multiplexer;
    private readonly string _prefix;

    /// <summary>Initializes a new instance of the <see cref="RedisCertificateStore"/> class.</summary>
    public RedisCertificateStore(IConnectionMultiplexer multiplexer, IOptions<RedisStoreOptions> options)
    {
        ArgumentNullException.ThrowIfNull(multiplexer);
        ArgumentNullException.ThrowIfNull(options);

        _multiplexer = multiplexer;
        _prefix = options.Value.KeyPrefix ?? string.Empty;
    }

    /// <inheritdoc />
    public async Task<CertificateMaterial?> LoadAsync(string name, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        HashEntry[] entries = await _multiplexer.GetDatabase().HashGetAllAsync(Key(name));

        string? chain = null;
        string? key = null;
        foreach (HashEntry entry in entries)
        {
            if (entry.Name == ChainField)
            {
                chain = entry.Value;
            }
            else if (entry.Name == KeyField)
            {
                key = entry.Value;
            }
        }

        return chain is null || key is null ? null : new CertificateMaterial(chain, key);
    }

    /// <inheritdoc />
    public Task SaveAsync(string name, CertificateMaterial material, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(material);
        cancellationToken.ThrowIfCancellationRequested();

        return _multiplexer.GetDatabase().HashSetAsync(
            Key(name),
            [
                new HashEntry(ChainField, material.CertificateChainPem),
                new HashEntry(KeyField, material.PrivateKeyPem),
            ]);
    }

    private string Key(string name) => _prefix + "cert:" + name;
}
