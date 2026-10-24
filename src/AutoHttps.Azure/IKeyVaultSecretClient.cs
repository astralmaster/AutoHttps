using System;
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

    /// <summary>
    /// Sets a secret's value, creating it or adding a new version. Returns false, having written
    /// nothing, when the vault refuses the name with a conflict, which is what it does while a deleted
    /// secret of that name is still in its recycle bin.
    /// </summary>
    Task<bool> TrySetAsync(string name, string value, CancellationToken cancellationToken);

    /// <summary>
    /// Recovers a deleted secret of this name from the vault's recycle bin. Returns false when there is
    /// none to recover.
    /// </summary>
    Task<bool> RecoverDeletedAsync(string name, CancellationToken cancellationToken);
}

internal static class KeyVaultSecretWriter
{
    /// <summary>
    /// Writes a secret, recovering a deleted one of the same name first if that is what is in the way.
    /// Soft delete is on in every vault and cannot be turned off, and a deleted secret keeps its name
    /// for the whole retention period, 90 days by default. Deleting a certificate's secret to force a
    /// new one would otherwise make every later write fail, and every restart and every replica would
    /// order a certificate it then cannot keep, into the authority's duplicate-certificate limit.
    /// </summary>
    public static async Task SetAsync(this IKeyVaultSecretClient secrets, string name, string value, CancellationToken cancellationToken)
    {
        if (await secrets.TrySetAsync(name, value, cancellationToken))
        {
            return;
        }

        if (!await secrets.RecoverDeletedAsync(name, cancellationToken))
        {
            throw new InvalidOperationException(
                $"Key Vault refused to write the secret '{name}' with a conflict, and no deleted secret of that " +
                "name is waiting to be recovered.");
        }

        if (!await secrets.TrySetAsync(name, value, cancellationToken))
        {
            throw new InvalidOperationException(
                $"Key Vault recovered the deleted secret '{name}' but still refused to write it.");
        }
    }
}
