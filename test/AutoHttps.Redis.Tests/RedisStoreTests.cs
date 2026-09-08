using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.Redis.Tests;

[Collection(RedisCollection.Name)]
public sealed class RedisStoreTests
{
    private const string Chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----";
    private const string Key = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----";

    private readonly RedisFixture _redis;

    public RedisStoreTests(RedisFixture redis) => _redis = redis;

    [Fact]
    public async Task SavesAndLoadsCertificateMaterial()
    {
        RedisCertificateStore store = CertificateStore();
        var material = new CertificateMaterial(Chain, Key);

        await store.SaveAsync("example.com", material, CancellationToken.None);
        CertificateMaterial? loaded = await store.LoadAsync("example.com", CancellationToken.None);

        Assert.NotNull(loaded);
        Assert.Equal(Chain, loaded!.CertificateChainPem);
        Assert.Equal(Key, loaded.PrivateKeyPem);
    }

    [Fact]
    public async Task LoadingAnUnknownCertificateReturnsNull() =>
        Assert.Null(await CertificateStore().LoadAsync("does-not-exist", CancellationToken.None));

    [Fact]
    public async Task SavingOverwritesThePreviousMaterial()
    {
        RedisCertificateStore store = CertificateStore();

        await store.SaveAsync("d", new CertificateMaterial(Chain + "-A", Key + "-A"), CancellationToken.None);
        await store.SaveAsync("d", new CertificateMaterial(Chain + "-B", Key + "-B"), CancellationToken.None);

        CertificateMaterial? loaded = await store.LoadAsync("d", CancellationToken.None);
        Assert.Equal(Chain + "-B", loaded!.CertificateChainPem);
    }

    [Fact]
    public async Task SavesAndLoadsTheAccountKey()
    {
        RedisAccountKeyStore store = AccountKeyStore();

        await store.SaveAsync("acct", Key, CancellationToken.None);

        Assert.Equal(Key, await store.LoadAsync("acct", CancellationToken.None));
    }

    [Fact]
    public async Task LoadingAnUnknownAccountKeyReturnsNull() =>
        Assert.Null(await AccountKeyStore().LoadAsync("no-account", CancellationToken.None));

    private RedisCertificateStore CertificateStore() => new(_redis.Multiplexer, Options.Create(FreshOptions()));

    private RedisAccountKeyStore AccountKeyStore() => new(_redis.Multiplexer, Options.Create(FreshOptions()));

    // A unique prefix per store keeps tests from colliding on the shared Redis.
    private static RedisStoreOptions FreshOptions() =>
        new() { KeyPrefix = "autohttps-test:" + Guid.NewGuid().ToString("n") + ":" };
}
