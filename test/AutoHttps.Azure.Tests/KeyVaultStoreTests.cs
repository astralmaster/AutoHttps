using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Azure;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.Azure.Tests;

public sealed class KeyVaultStoreTests
{
    private const string Chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----";
    private const string Key = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----";

    [Fact]
    public async Task CertificateMaterialRoundTripsThroughASecret()
    {
        var vault = new FakeVault();
        KeyVaultCertificateStore store = CertificateStore(vault);

        await store.SaveAsync("acme_v02_example_com", new CertificateMaterial(Chain, Key), CancellationToken.None);
        CertificateMaterial? loaded = await store.LoadAsync("acme_v02_example_com", CancellationToken.None);

        Assert.NotNull(loaded);
        Assert.Equal(Chain, loaded!.CertificateChainPem);
        Assert.Equal(Key, loaded.PrivateKeyPem);
    }

    [Fact]
    public async Task LoadingAnAbsentCertificateReturnsNull() =>
        Assert.Null(await CertificateStore(new FakeVault()).LoadAsync("missing", CancellationToken.None));

    [Fact]
    public async Task AccountKeyRoundTripsThroughASecret()
    {
        var vault = new FakeVault();
        KeyVaultAccountKeyStore store = AccountKeyStore(vault);

        await store.SaveAsync("acme_account", Key, CancellationToken.None);

        Assert.Equal(Key, await store.LoadAsync("acme_account", CancellationToken.None));
    }

    [Theory]
    [InlineData("acme_v02_api_letsencrypt_org.directory")]
    [InlineData("simple")]
    public void SecretNamesAreKeyVaultValid(string identifier)
    {
        string name = KeyVaultSecretNames.For("autohttps-", "cert", identifier);

        Assert.Matches("^[a-zA-Z0-9-]+$", name);
        Assert.True(name.Length <= 127);
    }

    [Fact]
    public void SecretNamesAreStableAndDistinct()
    {
        string first = KeyVaultSecretNames.For("autohttps-", "cert", "example.com");
        string same = KeyVaultSecretNames.For("autohttps-", "cert", "example.com");
        string other = KeyVaultSecretNames.For("autohttps-", "cert", "different.com");

        Assert.Equal(first, same);
        Assert.NotEqual(first, other);
    }

    private static KeyVaultCertificateStore CertificateStore(FakeVault vault) =>
        new(vault, Options.Create(new AzureKeyVaultOptions { VaultUri = new Uri("https://v.vault.azure.net/") }));

    private static KeyVaultAccountKeyStore AccountKeyStore(FakeVault vault) =>
        new(vault, Options.Create(new AzureKeyVaultOptions { VaultUri = new Uri("https://v.vault.azure.net/") }));

    private sealed class FakeVault : IKeyVaultSecretClient
    {
        private readonly Dictionary<string, string> _store = new(StringComparer.Ordinal);

        public Task<string?> GetAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(_store.TryGetValue(name, out string? value) ? value : null);

        public Task SetAsync(string name, string value, CancellationToken cancellationToken)
        {
            _store[name] = value;
            return Task.CompletedTask;
        }
    }
}
