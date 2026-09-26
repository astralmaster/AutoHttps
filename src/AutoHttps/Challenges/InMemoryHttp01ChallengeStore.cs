using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Challenges;

/// <summary>
/// The default <c>http-01</c> challenge store. Tokens live in this process only, which is enough for a
/// single instance and is why replicas behind one DNS name need a shared store instead.
/// </summary>
internal sealed class InMemoryHttp01ChallengeStore : IHttp01ChallengeStore
{
    private readonly ConcurrentDictionary<string, string> _pending = new(StringComparer.Ordinal);

    public bool IsProcessLocal => true;

    internal int Count => _pending.Count;

    public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken)
    {
        _pending[token] = keyAuthorization;
        return Task.CompletedTask;
    }

    public Task<string?> GetAsync(string token, CancellationToken cancellationToken) =>
        Task.FromResult(_pending.TryGetValue(token, out string? keyAuthorization) ? keyAuthorization : null);

    public Task RemoveAsync(string token, CancellationToken cancellationToken)
    {
        _pending.TryRemove(token, out _);
        return Task.CompletedTask;
    }
}
