using System;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;

namespace AutoHttps.Azure;

/// <summary>Translates the stores' needs into Key Vault SDK calls.</summary>
internal sealed class KeyVaultSecretClientAdapter : IKeyVaultSecretClient
{
    private const int Forbidden = 403;
    private const int NotFound = 404;
    private const int Conflict = 409;

    private readonly SecretClient _client;

    public KeyVaultSecretClientAdapter(Uri vaultUri, TokenCredential credential) =>
        _client = new SecretClient(vaultUri, credential);

    public async Task<string?> GetAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            Response<KeyVaultSecret> response = await _client.GetSecretAsync(name, cancellationToken: cancellationToken);
            return response.Value.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async Task<bool> TrySetAsync(string name, string value, CancellationToken cancellationToken)
    {
        try
        {
            await _client.SetSecretAsync(name, value, cancellationToken);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == Conflict)
        {
            return false;
        }
    }

    public async Task<bool> RecoverDeletedAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            RecoverDeletedSecretOperation operation = await _client.StartRecoverDeletedSecretAsync(name, cancellationToken);
            await operation.WaitForCompletionAsync(cancellationToken);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == NotFound)
        {
            return false;
        }
        catch (RequestFailedException ex) when (ex.Status == Forbidden)
        {
            throw new InvalidOperationException(
                $"The Key Vault secret '{name}' was deleted and is still in the vault's recycle bin, so it cannot be " +
                "written again until it is recovered or purged. Recovering it needs the Recover permission on " +
                "secrets, which this identity does not have. Grant it, or recover or purge the secret yourself.",
                ex);
        }
    }
}
