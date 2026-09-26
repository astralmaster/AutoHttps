using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps;

/// <summary>
/// Holds the answer to a pending <c>http-01</c> challenge between the moment AutoHttps publishes it
/// and the moment the certificate authority fetches it.
/// </summary>
/// <remarks>
/// The default store keeps tokens in memory, which is enough for a single instance. Replicas behind
/// one DNS name need a store every replica can read, because the authority's validation request lands
/// on whichever replica the load balancer picks, not on the one that ordered the certificate. Replace
/// it with <see cref="IAutoHttpsBuilder.UseHttp01ChallengeStore{TStore}()"/>, or use
/// <c>AutoHttps.Redis</c>, which registers a Redis-backed store.
/// </remarks>
public interface IHttp01ChallengeStore
{
    /// <summary>
    /// Whether this store is private to one process. The in-memory default is; a store every replica
    /// can read is not.
    /// </summary>
    /// <remarks>
    /// AutoHttps uses this only to explain a failed validation. With a process-local store, never being
    /// asked for a token means something in front of the application answered the challenge path
    /// instead, which is worth saying. With a shared store another replica may have answered it, so
    /// that conclusion would be wrong and is not drawn.
    /// </remarks>
    bool IsProcessLocal { get; }

    /// <summary>Publishes the answer to a challenge.</summary>
    /// <param name="token">The challenge token, which appears in the request path.</param>
    /// <param name="keyAuthorization">The value to return for that token.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <returns>A task that completes once the answer can be read back.</returns>
    Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken);

    /// <summary>Reads the answer to a challenge.</summary>
    /// <param name="token">The challenge token taken from the request path.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <returns>
    /// The key authorization to return, or <see langword="null"/> when no challenge with this token is
    /// pending. A miss is ordinary: anything may request the challenge path.
    /// </returns>
    Task<string?> GetAsync(string token, CancellationToken cancellationToken);

    /// <summary>Removes a challenge once it has been validated or abandoned.</summary>
    /// <param name="token">The challenge token.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <returns>A task that completes once the answer is gone.</returns>
    /// <remarks>
    /// This may be called for a token that was never added, because publishing can fail partway.
    /// Removing something that is not there should succeed rather than throw.
    /// </remarks>
    Task RemoveAsync(string token, CancellationToken cancellationToken);
}
