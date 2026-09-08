using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Azure;

/// <summary>
/// The slice of Key Vault the stores use. Keeping the SDK behind this seam lets the store logic be
/// tested without a live vault.
/// </summary>
internal interface IKeyVaultSecretClient
{
    /// <summary>The value of a secret, or null if it does not exist.</summary>
    Task<string?> GetAsync(string name, CancellationToken cancellationToken);

    /// <summary>Sets a secret's value, creating it or adding a new version.</summary>
    Task SetAsync(string name, string value, CancellationToken cancellationToken);
}
