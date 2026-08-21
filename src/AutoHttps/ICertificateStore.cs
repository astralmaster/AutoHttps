using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps;

/// <summary>
/// Persists issued certificates so that they survive a restart and can be shared between instances.
/// </summary>
/// <remarks>
/// Implementations must be safe to call concurrently. A store that loses data will cause the
/// application to request a new certificate on every start, which will quickly exhaust the
/// certificate authority's rate limits.
/// </remarks>
public interface ICertificateStore
{
    /// <summary>Loads previously saved certificate material.</summary>
    /// <param name="name">A stable identifier for the certificate, derived from the domain set.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <returns>The saved material, or <see langword="null"/> if nothing has been saved under this name.</returns>
    Task<CertificateMaterial?> LoadAsync(string name, CancellationToken cancellationToken);

    /// <summary>Saves certificate material, replacing anything already stored under the same name.</summary>
    /// <param name="name">A stable identifier for the certificate, derived from the domain set.</param>
    /// <param name="material">The certificate chain and private key to save.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    Task SaveAsync(string name, CertificateMaterial material, CancellationToken cancellationToken);
}

/// <summary>
/// Persists the ACME account key. The same key must be reused across restarts so that the
/// application keeps its registration and its rate limit allowance with the certificate authority.
/// </summary>
public interface IAccountKeyStore
{
    /// <summary>Loads the saved account key.</summary>
    /// <param name="name">A stable identifier derived from the certificate authority and contact address.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <returns>The PKCS#8 PEM encoded key, or <see langword="null"/> if no account has been created yet.</returns>
    Task<string?> LoadAsync(string name, CancellationToken cancellationToken);

    /// <summary>Saves the account key.</summary>
    /// <param name="name">A stable identifier derived from the certificate authority and contact address.</param>
    /// <param name="privateKeyPem">The PKCS#8 PEM encoded key.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    Task SaveAsync(string name, string privateKeyPem, CancellationToken cancellationToken);
}
