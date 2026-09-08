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

    public async Task SetAsync(string name, string value, CancellationToken cancellationToken) =>
        await _client.SetSecretAsync(name, value, cancellationToken);
}
