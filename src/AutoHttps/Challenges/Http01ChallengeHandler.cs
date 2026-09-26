using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;

namespace AutoHttps.Challenges;

internal sealed class Http01ChallengeHandler : IChallengeHandler
{
    private readonly IHttp01ChallengeStore _store;
    private readonly Http01RequestProbe _probe;

    public Http01ChallengeHandler(IHttp01ChallengeStore store, Http01RequestProbe probe)
    {
        _store = store;
        _probe = probe;
    }

    public string ChallengeType => ChallengeTypes.Http01;

    public bool CanHandle(string identifierType) =>
        identifierType is AcmeIdentifierTypes.Dns or AcmeIdentifierTypes.Ip;

    public Task PrepareAsync(ChallengeContext context, CancellationToken cancellationToken) =>
        _store.AddAsync(context.Token, context.KeyAuthorization, cancellationToken);

    public async Task CleanupAsync(ChallengeContext context, CancellationToken cancellationToken)
    {
        // Forget the token even if the store cannot be reached. A cleanup failure is caught and logged
        // by the caller, so without this a store that keeps throwing would leave an entry behind on
        // every attempt.
        try
        {
            await _store.RemoveAsync(context.Token, cancellationToken);
        }
        finally
        {
            _probe.Forget(context.Token);
        }
    }

    public string? DescribeFailure(ChallengeContext context, AcmeException failure)
    {
        if (_probe.WasServed(context.Token))
        {
            return null;
        }

        // Nothing arriving here means either that the authority never got this far or that it was
        // answered by something else. Only its own error tells the two apart, and pointing at a
        // proxy that does not exist costs more time than saying nothing would have.
        return failure.ErrorType switch
        {
            AcmeErrorTypes.Unauthorized or AcmeErrorTypes.IncorrectResponse => AnsweredBySomethingElse(),
            AcmeErrorTypes.Dns =>
                "the authority could not resolve the name, so it never reached this application. " +
                "Check that public DNS for this name resolves to this host",
            AcmeErrorTypes.Connection =>
                "the authority could not connect, so it never reached this application. An http-01 " +
                "validation always starts on port 80, so check that port 80 is reachable from the " +
                "public internet and forwarded to this process",
            _ => _store.IsProcessLocal
                ? "the challenge response was published but nothing ever requested it from this process, " +
                  "so the authority never reached the application"
                : "the challenge response was published but nothing requested it from this process. The " +
                  "challenge store is shared, so another replica may have served it and the authority " +
                  "still never reached any of them",
        };
    }

    // The authority reached something and did not get the answer it expected. With a store private to
    // this process, nothing asking here means something in front of the application answered instead.
    // With a shared store another replica could legitimately have answered, so that conclusion would be
    // wrong; what is worth checking then is that every replica reaches the same store.
    private string AnsweredBySomethingElse() => _store.IsProcessLocal
        ? "the challenge response was published but nothing ever requested it from this process, " +
          "so something in front of the application answered /.well-known/acme-challenge instead. " +
          "Look for a proxy, ingress controller or CDN intercepting that path"
        : "the challenge response was published but nothing requested it from this process, and the " +
          "answer the authority did get was wrong. Check that every replica reads the same challenge " +
          "store, and that no proxy, ingress controller or CDN answers /.well-known/acme-challenge";
}
