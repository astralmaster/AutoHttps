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

    [Fact]
    public async Task ACertificateCanBeSavedAgainAfterItsSecretWasDeleted()
    {
        // Every vault soft-deletes, and a deleted secret keeps its name for the retention period.
        // Deleting the secret to force a new certificate is the obvious move, and without recovery every
        // later write would fail, so every restart would order a certificate it then cannot keep.
        var vault = new FakeVault();
        KeyVaultCertificateStore store = CertificateStore(vault);

        await store.SaveAsync("site", new CertificateMaterial(Chain, Key), CancellationToken.None);
        vault.SoftDelete(KeyVaultSecretNames.For("autohttps-", "cert", "site"));
        Assert.Null(await store.LoadAsync("site", CancellationToken.None));

        await store.SaveAsync("site", new CertificateMaterial(Chain + "-new", Key + "-new"), CancellationToken.None);

        CertificateMaterial? loaded = await store.LoadAsync("site", CancellationToken.None);
        Assert.Equal(Chain + "-new", loaded!.CertificateChainPem);
        Assert.Equal(1, vault.Recoveries);
    }

    [Fact]
    public async Task AnAccountKeyCanBeSavedAgainAfterItsSecretWasDeleted()
    {
        var vault = new FakeVault();
        KeyVaultAccountKeyStore store = AccountKeyStore(vault);

        await store.SaveAsync("acct", Key, CancellationToken.None);
        vault.SoftDelete(KeyVaultSecretNames.For("autohttps-", "account", "acct"));

        await store.SaveAsync("acct", Key + "-new", CancellationToken.None);

        Assert.Equal(Key + "-new", await store.LoadAsync("acct", CancellationToken.None));
    }

    [Fact]
    public async Task AConflictWithNothingToRecoverIsReportedRatherThanIgnored()
    {
        var vault = new FakeVault { ConflictWithoutDeletedSecret = true };
        KeyVaultCertificateStore store = CertificateStore(vault);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.SaveAsync("site", new CertificateMaterial(Chain, Key), CancellationToken.None));

        Assert.Contains("conflict", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Holds secrets the way Key Vault does with soft delete on, which it always is: a deleted secret
    /// moves to a recycle bin, keeps its name there, and blocks a new secret of that name with a
    /// conflict until it is recovered.
    /// </summary>
    private sealed class FakeVault : IKeyVaultSecretClient
    {
        private readonly Dictionary<string, string> _store = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _deleted = new(StringComparer.Ordinal);

        public bool ConflictWithoutDeletedSecret { get; init; }

        public int Recoveries { get; private set; }

        public void SoftDelete(string name)
        {
            _deleted[name] = _store[name];
            _store.Remove(name);
        }

        public Task<string?> GetAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(_store.TryGetValue(name, out string? value) ? value : null);

        public Task<bool> TrySetAsync(string name, string value, CancellationToken cancellationToken)
        {
            if (ConflictWithoutDeletedSecret || _deleted.ContainsKey(name))
            {
                return Task.FromResult(false);
            }

            _store[name] = value;
            return Task.FromResult(true);
        }

        public Task<bool> RecoverDeletedAsync(string name, CancellationToken cancellationToken)
        {
            if (!_deleted.Remove(name, out string? value))
            {
                return Task.FromResult(false);
            }

            Recoveries++;
            _store[name] = value;
            return Task.FromResult(true);
        }
    }
}
