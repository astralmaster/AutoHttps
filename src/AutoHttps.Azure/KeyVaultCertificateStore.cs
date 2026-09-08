using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace AutoHttps.Azure;

/// <summary>
/// Stores issued certificates as Key Vault secrets, so instances share certificates through the vault.
/// Each certificate is one secret holding the chain and the private key.
/// </summary>
public sealed class KeyVaultCertificateStore : ICertificateStore
{
    private const string Kind = "cert";

    private readonly IKeyVaultSecretClient _secrets;
    private readonly string _prefix;

    internal KeyVaultCertificateStore(IKeyVaultSecretClient secrets, IOptions<AzureKeyVaultOptions> options)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(options);

        _secrets = secrets;
        _prefix = options.Value.SecretPrefix ?? string.Empty;
    }

    /// <inheritdoc />
    public async Task<CertificateMaterial?> LoadAsync(string name, CancellationToken cancellationToken)
    {
        string? json = await _secrets.GetAsync(SecretName(name), cancellationToken);
        if (json is null)
        {
            return null;
        }

        using JsonDocument document = JsonDocument.Parse(json);
        string? chain = document.RootElement.TryGetProperty("chain", out JsonElement c) ? c.GetString() : null;
        string? key = document.RootElement.TryGetProperty("key", out JsonElement k) ? k.GetString() : null;

        return chain is null || key is null ? null : new CertificateMaterial(chain, key);
    }

    /// <inheritdoc />
    public Task SaveAsync(string name, CertificateMaterial material, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(material);
        return _secrets.SetAsync(SecretName(name), Serialize(material), cancellationToken);
    }

    private string SecretName(string name) => KeyVaultSecretNames.For(_prefix, Kind, name);

    private static string Serialize(CertificateMaterial material)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("chain", material.CertificateChainPem);
            writer.WriteString("key", material.PrivateKeyPem);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
