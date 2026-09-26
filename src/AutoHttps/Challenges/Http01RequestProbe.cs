using System;
using System.Collections.Concurrent;

namespace AutoHttps.Challenges;

/// <summary>
/// Records which challenge tokens this process answered, so a failed validation can say whether the
/// request ever arrived here. It is deliberately separate from the challenge store: the store may be
/// shared between replicas, while this is always about this process.
/// </summary>
/// <remarks>
/// An entry is added only for a token this process actually served and is dropped when the challenge is
/// cleaned up, so the set stays as small as the number of challenges in flight.
/// </remarks>
internal sealed class Http01RequestProbe
{
    private readonly ConcurrentDictionary<string, byte> _served = new(StringComparer.Ordinal);

    public void MarkServed(string token) => _served[token] = 0;

    public bool WasServed(string token) => _served.ContainsKey(token);

    public void Forget(string token) => _served.TryRemove(token, out _);
}
