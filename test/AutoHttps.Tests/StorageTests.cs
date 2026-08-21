using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.Renewal;
using Xunit;

namespace AutoHttps.Tests;

public class StoreKeyTests
{
    private static readonly Uri Authority = new("https://acme.example.com/directory");

    [Fact]
    public void ForCertificate_SeparatesAuthoritiesSoAStagingCertificateIsNeverServedInProduction()
    {
        var staging = new Uri("https://acme-staging-v02.api.letsencrypt.org/directory");
        var production = new Uri("https://acme-v02.api.letsencrypt.org/directory");

        // Moving from staging to production is the normal way to launch. Reusing the same storage
        // must not let the untrusted staging certificate be picked back up.
        Assert.NotEqual(
            StoreKey.ForCertificate(staging, ["example.com"]),
            StoreKey.ForCertificate(production, ["example.com"]));
    }

    [Fact]
    public void ForCertificate_IsIndependentOfTheOrderTheDomainsWereListedIn() =>
        Assert.Equal(
            StoreKey.ForCertificate(Authority, ["a.example.com", "b.example.com"]),
            StoreKey.ForCertificate(Authority, ["b.example.com", "a.example.com"]));

    [Fact]
    public void ForCertificate_ChangesWhenADomainIsAdded() =>
        Assert.NotEqual(
            StoreKey.ForCertificate(Authority, ["a.example.com"]),
            StoreKey.ForCertificate(Authority, ["a.example.com", "b.example.com"]));

    [Fact]
    public void ForCertificate_ProducesANameThatIsSafeOnDisk()
    {
        string name = StoreKey.ForCertificate(Authority, ["*.example.com"]);

        Assert.DoesNotContain('*', name);
        Assert.Equal(-1, name.IndexOfAny(Path.GetInvalidFileNameChars()));
        Assert.StartsWith("wildcard.example.com-", name, StringComparison.Ordinal);
    }

    [Fact]
    public void ForCertificate_KeepsNamesShortEnoughForAFilesystem()
    {
        string longDomain = string.Join('.', Enumerable.Repeat("abcdefghij", 20)) + ".com";

        Assert.True(StoreKey.ForCertificate(Authority, [longDomain]).Length <= 64);
    }

    [Fact]
    public void ForAccount_SeparatesAuthoritiesAndContacts()
    {
        var authority = new Uri("https://acme.example.com/directory");
        var other = new Uri("https://acme.other.com/directory");

        Assert.NotEqual(StoreKey.ForAccount(authority, "a@example.com"), StoreKey.ForAccount(other, "a@example.com"));
        Assert.NotEqual(StoreKey.ForAccount(authority, "a@example.com"), StoreKey.ForAccount(authority, "b@example.com"));
        Assert.Equal(StoreKey.ForAccount(authority, "a@example.com"), StoreKey.ForAccount(authority, "a@example.com"));
    }
}

public class FileSystemStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "autohttps-tests", Guid.NewGuid().ToString("n"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task LoadAsync_ReturnsNullBeforeAnythingIsSaved() =>
        Assert.Null(await new FileSystemStore(_root).LoadAsync("missing", CancellationToken.None));

    [Fact]
    public async Task SaveAsync_ThenLoadAsync_RoundTripsTheMaterial()
    {
        var store = new FileSystemStore(_root);
        var material = new CertificateMaterial("-----BEGIN CERTIFICATE-----\nchain\n", "-----BEGIN PRIVATE KEY-----\nkey\n");

        await store.SaveAsync("site", material, CancellationToken.None);
        CertificateMaterial? loaded = await store.LoadAsync("site", CancellationToken.None);

        Assert.NotNull(loaded);
        Assert.Equal(material.CertificateChainPem, loaded.CertificateChainPem);
        Assert.Equal(material.PrivateKeyPem, loaded.PrivateKeyPem);
    }

    [Fact]
    public async Task SaveAsync_ReplacesAPreviousCertificate()
    {
        var store = new FileSystemStore(_root);

        await store.SaveAsync("site", new CertificateMaterial("first", "key1"), CancellationToken.None);
        await store.SaveAsync("site", new CertificateMaterial("second", "key2"), CancellationToken.None);

        CertificateMaterial? loaded = await store.LoadAsync("site", CancellationToken.None);
        Assert.Equal("second", loaded!.CertificateChainPem);
        Assert.Equal("key2", loaded.PrivateKeyPem);
    }

    [Fact]
    public async Task SaveAsync_PublishesNothingWhenTheKeyCannotBeWritten()
    {
        var store = new FileSystemStore(_root);
        Directory.CreateDirectory(_root);

        // A directory where the key file should go makes writing it fail, standing in for the disk
        // filling up between the two halves. Publishing the certificate alone would leave a store
        // that cannot be used and costs a duplicate certificate on the next start.
        Directory.CreateDirectory(Path.Combine(_root, "site.key.pem"));

        await Assert.ThrowsAnyAsync<Exception>(
            () => store.SaveAsync("site", new CertificateMaterial("chain", "key"), CancellationToken.None));

        Assert.Empty(Directory.GetFiles(_root, "site.crt.pem"));
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
    }

    [Fact]
    public async Task SaveAsync_LeavesNoTemporaryFilesBehind()
    {
        var store = new FileSystemStore(_root);
        await store.SaveAsync("site", new CertificateMaterial("chain", "key"), CancellationToken.None);

        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
    }

    [Fact]
    public async Task AccountKey_RoundTripsSeparatelyFromCertificates()
    {
        IAccountKeyStore store = new FileSystemStore(_root);

        Assert.Null(await store.LoadAsync("account", CancellationToken.None));

        await store.SaveAsync("account", "-----BEGIN PRIVATE KEY-----\nacct\n", CancellationToken.None);

        Assert.Equal("-----BEGIN PRIVATE KEY-----\nacct\n", await store.LoadAsync("account", CancellationToken.None));
    }

    [Fact]
    public async Task LoadAsync_TreatsAHalfWrittenPairAsMissing()
    {
        var store = new FileSystemStore(_root);
        await store.SaveAsync("site", new CertificateMaterial("chain", "key"), CancellationToken.None);

        File.Delete(Path.Combine(_root, "site.key.pem"));

        Assert.Null(await store.LoadAsync("site", CancellationToken.None));
    }

    [Fact]
    public async Task LoadAsync_TreatsAnEmptyFileAsMissing()
    {
        var store = new FileSystemStore(_root);
        await store.SaveAsync("site", new CertificateMaterial("chain", "key"), CancellationToken.None);

        await File.WriteAllTextAsync(Path.Combine(_root, "site.crt.pem"), string.Empty);

        Assert.Null(await store.LoadAsync("site", CancellationToken.None));
    }

    [Fact]
    public async Task RestrictsPermissionsOnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var store = new FileSystemStore(_root);
        await store.SaveAsync("site", new CertificateMaterial("chain", "key"), CancellationToken.None);

        UnixFileMode mode = File.GetUnixFileMode(Path.Combine(_root, "site.key.pem"));

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
    }
}

public class InMemoryStoreTests
{
    [Fact]
    public async Task RoundTripsCertificatesAndAccountKeys()
    {
        var store = new InMemoryStore();
        IAccountKeyStore accountKeys = store;

        Assert.Null(await store.LoadAsync("site", CancellationToken.None));

        await store.SaveAsync("site", new CertificateMaterial("chain", "key"), CancellationToken.None);
        await accountKeys.SaveAsync("account", "pem", CancellationToken.None);

        Assert.Equal("chain", (await store.LoadAsync("site", CancellationToken.None))!.CertificateChainPem);
        Assert.Equal("pem", await accountKeys.LoadAsync("account", CancellationToken.None));
    }
}

public class FileSystemLockTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "autohttps-tests", Guid.NewGuid().ToString("n"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task OnlyOneHolderCanTakeTheSameLock()
    {
        var first = new FileSystemLock(_root);
        var second = new FileSystemLock(_root);

        await using IAsyncDisposable? held = await first.TryAcquireAsync("site", CancellationToken.None);
        Assert.NotNull(held);

        Assert.Null(await second.TryAcquireAsync("site", CancellationToken.None));
    }

    [Fact]
    public async Task DifferentNamesDoNotBlockEachOther()
    {
        var distributedLock = new FileSystemLock(_root);

        await using IAsyncDisposable? first = await distributedLock.TryAcquireAsync("site-a", CancellationToken.None);
        await using IAsyncDisposable? second = await distributedLock.TryAcquireAsync("site-b", CancellationToken.None);

        Assert.NotNull(first);
        Assert.NotNull(second);
    }

    [Fact]
    public async Task TheLockIsReleasedWhenTheHandleIsDisposed()
    {
        var distributedLock = new FileSystemLock(_root);

        IAsyncDisposable? first = await distributedLock.TryAcquireAsync("site", CancellationToken.None);
        Assert.NotNull(first);
        await first.DisposeAsync();

        await using IAsyncDisposable? second = await distributedLock.TryAcquireAsync("site", CancellationToken.None);
        Assert.NotNull(second);
    }

    [Fact]
    public async Task AnUnwritableDirectoryIsReportedAsSuchRatherThanAsContention()
    {
        // A file where the storage directory should be stands in for any reason the directory cannot
        // be used: a read-only mount, or a volume owned by a different user.
        Directory.CreateDirectory(_root);
        string blocked = Path.Combine(_root, "blocked");
        await File.WriteAllTextAsync(blocked, "not a directory");

        var distributedLock = new FileSystemLock(blocked);

        // Returning null here would be read as "another instance is working on it", and the
        // application would wait forever for a sibling that does not exist.
        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => distributedLock.TryAcquireAsync("site", CancellationToken.None));

        Assert.Contains("cannot be written to", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheNullLockAlwaysSucceeds()
    {
        var distributedLock = new NullDistributedLock();

        await using IAsyncDisposable? first = await distributedLock.TryAcquireAsync("site", CancellationToken.None);
        await using IAsyncDisposable? second = await distributedLock.TryAcquireAsync("site", CancellationToken.None);

        Assert.NotNull(first);
        Assert.NotNull(second);
    }
}
