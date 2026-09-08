using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace AutoHttps.Azure;

/// <summary>
/// Stores the ACME account key as a Key Vault secret, so instances keep one shared registration.
/// </summary>
public sealed class KeyVaultAccountKeyStore : IAccountKeyStore
{
    private const string Kind = "account";

    private readonly IKeyVaultSecretClient _secrets;
    private readonly string _prefix;

    internal KeyVaultAccountKeyStore(IKeyVaultSecretClient secrets, IOptions<AzureKeyVaultOptions> options)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(options);

        _secrets = secrets;
        _prefix = options.Value.SecretPrefix ?? string.Empty;
    }

    /// <inheritdoc />
    public Task<string?> LoadAsync(string name, CancellationToken cancellationToken) =>
        _secrets.GetAsync(SecretName(name), cancellationToken);

    /// <inheritdoc />
    public Task SaveAsync(string name, string privateKeyPem, CancellationToken cancellationToken) =>
        _secrets.SetAsync(SecretName(name), privateKeyPem, cancellationToken);

    private string SecretName(string name) => KeyVaultSecretNames.For(_prefix, Kind, name);
}
