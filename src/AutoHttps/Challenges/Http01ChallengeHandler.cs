using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;

namespace AutoHttps.Challenges;

internal sealed class Http01ChallengeStore
{
    private readonly ConcurrentDictionary<string, PendingChallenge> _pending = new(StringComparer.Ordinal);

    public int Count => _pending.Count;

    public void Add(string token, string keyAuthorization) =>
        _pending[token] = new PendingChallenge(keyAuthorization);

    public void Remove(string token) => _pending.TryRemove(token, out _);

    public bool TryGet(string token, [NotNullWhen(true)] out string? keyAuthorization)
    {
        if (_pending.TryGetValue(token, out PendingChallenge? pending))
        {
            pending.MarkRequested();
            keyAuthorization = pending.KeyAuthorization;
            return true;
        }

        keyAuthorization = null;
        return false;
    }

    /// <summary>Whether anything ever asked this process for the token.</summary>
    public bool WasRequested(string token) =>
        _pending.TryGetValue(token, out PendingChallenge? pending) && pending.WasRequested;

    private sealed class PendingChallenge
    {
        private int _requested;

        public PendingChallenge(string keyAuthorization) => KeyAuthorization = keyAuthorization;

        public string KeyAuthorization { get; }

        public bool WasRequested => Volatile.Read(ref _requested) != 0;

        public void MarkRequested() => Volatile.Write(ref _requested, 1);
    }
}

internal sealed class Http01ChallengeHandler : IChallengeHandler
{
    private readonly Http01ChallengeStore _store;

    public Http01ChallengeHandler(Http01ChallengeStore store) => _store = store;

    public string ChallengeType => ChallengeTypes.Http01;

    public bool CanHandle(string identifierType) =>
        identifierType is AcmeIdentifierTypes.Dns or AcmeIdentifierTypes.Ip;

    public Task PrepareAsync(ChallengeContext context, CancellationToken cancellationToken)
    {
        _store.Add(context.Token, context.KeyAuthorization);
        return Task.CompletedTask;
    }

    public Task CleanupAsync(ChallengeContext context, CancellationToken cancellationToken)
    {
        _store.Remove(context.Token);
        return Task.CompletedTask;
    }

    public string? DescribeFailure(ChallengeContext context, AcmeException failure)
    {
        if (_store.WasRequested(context.Token))
        {
            return null;
        }

        // Nothing arriving here means either that the authority never got this far or that it was
        // answered by something else. Only its own error tells the two apart, and pointing at a
        // proxy that does not exist costs more time than saying nothing would have.
        return failure.ErrorType switch
        {
            AcmeErrorTypes.Unauthorized or AcmeErrorTypes.IncorrectResponse =>
                "the challenge response was published but nothing ever requested it from this process, " +
                "so something in front of the application answered /.well-known/acme-challenge instead. " +
                "Look for a proxy, ingress controller or CDN intercepting that path",
            AcmeErrorTypes.Dns =>
                "the authority could not resolve the name, so it never reached this application. " +
                "Check that public DNS for this name resolves to this host",
            AcmeErrorTypes.Connection =>
                "the authority could not connect, so it never reached this application. An http-01 " +
                "validation always starts on port 80, so check that port 80 is reachable from the " +
                "public internet and forwarded to this process",
            _ =>
                "the challenge response was published but nothing ever requested it from this process, " +
                "so the authority never reached the application",
        };
    }
}
