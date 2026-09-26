using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// Replicas behind one DNS name only pass an http-01 validation if the replica the load balancer hands
/// the request to can read the answer the ordering replica published. These pin that down without
/// depending on which replica wins the lock: the replica that orders cannot answer its own challenge
/// (its responder is switched off) and the replica the authority is sent to can never order (its
/// authority is unreachable), so the validation can only succeed through the shared store.
/// </summary>
public class SharedChallengeStoreTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    // Long enough for several retries at the test application's two second ceiling.
    private static readonly TimeSpan FailureTimeout = TimeSpan.FromSeconds(15);

    [Fact]
    public async Task AReplicaThatDidNotOrderAnswersTheChallengeFromASharedStore()
    {
        using var ordering = new TempStorage();
        using var serving = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        var shared = new SharedChallengeStore();

        await using TestApplication orderer = await StartOrdererAsync(authority, ordering, shared);
        await using TestApplication responder = await StartResponderAsync(authority, serving, shared);

        // Every validation goes to the replica that cannot order, so the only way it can answer is by
        // reading what the ordering replica published.
        authority.HttpChallengeResolver = _ => responder.HttpBaseAddress;

        ServerCertificate certificate = await orderer.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(["app.example.com"], certificate.SubjectNames.ToArray());
        Assert.True(shared.Reads > 0, "the serving replica never read the shared store");
    }

    [Fact]
    public async Task AnyReplicaBehindOneNameCanAnswerFromASharedStore()
    {
        // Closer to a real load balancer than the test above: both replicas run a responder and the
        // authority is handed a different one each time, so every replica has to be able to answer.
        // The counter starts such that the first validation goes to the replica that cannot order,
        // which is the case that needs the shared store.
        using var ordering = new TempStorage();
        using var serving = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        var shared = new SharedChallengeStore();

        await using TestApplication orderer = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = ordering.Path;
            },
            configureServices: Share(shared));

        await using TestApplication responder = await StartResponderAsync(authority, serving, shared);

        Uri[] replicas = [orderer.HttpBaseAddress, responder.HttpBaseAddress];
        int handed = 0;
        authority.HttpChallengeResolver = _ => replicas[Interlocked.Increment(ref handed) % replicas.Length];

        ServerCertificate certificate = await orderer.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(["app.example.com"], certificate.SubjectNames.ToArray());
        Assert.True(shared.Reads > 0, "no replica read the shared store");
    }

    [Fact]
    public async Task WithoutASharedStoreTheReplicaThatDidNotOrderCannotAnswer()
    {
        // The negative control for the test above. With a store private to each process the serving
        // replica has nothing to answer with, so the order must fail rather than quietly succeed.
        using var ordering = new TempStorage();
        using var serving = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication orderer = await StartOrdererAsync(authority, ordering, store: null);
        await using TestApplication responder = await StartResponderAsync(authority, serving, store: null);

        authority.HttpChallengeResolver = _ => responder.HttpBaseAddress;

        // A fixed window rather than "wait for the first failure": retries here are at most two seconds
        // apart, so this is several attempts, and every one of them has to fail. Waiting only for a
        // failure would also be satisfied by a single early attempt and would not prove the order never
        // succeeds.
        await Task.Delay(FailureTimeout);

        Assert.Null(orderer.FindCertificate("app.example.com"));
        Assert.True(
            orderer.Log.CountOf(110) > 0,
            "the order should have failed:" + Environment.NewLine + orderer.Log.Describe());
    }

    /// <summary>
    /// The replica that orders. Its own challenge responder is switched off, so it cannot satisfy its
    /// own validation and the answer has to be served by the other replica.
    /// </summary>
    private static Task<TestApplication> StartOrdererAsync(
        TestCertificateAuthority authority,
        TempStorage storage,
        SharedChallengeStore? store) =>
        TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
                options.HandleHttp01Requests = false;
            },
            configureServices: Share(store));

    /// <summary>
    /// The replica the authority is pointed at. Its authority is unreachable so it never obtains a
    /// certificate of its own, and a separate storage directory keeps it out of the other replica's lock.
    /// </summary>
    private static Task<TestApplication> StartResponderAsync(
        TestCertificateAuthority authority,
        TempStorage storage,
        SharedChallengeStore? store) =>
        TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
                options.CertificateAuthority = new Uri("http://127.0.0.1:1/dir");
            },
            configureServices: Share(store));

    private static Action<IServiceCollection>? Share(SharedChallengeStore? store) =>
        store is null
            ? null
            : services => services.Replace(ServiceDescriptor.Singleton<IHttp01ChallengeStore>(store));

    /// <summary>
    /// Stands in for a Redis-backed store: one instance handed to both replicas, reporting itself as
    /// shared so the failure diagnosis does not blame a proxy.
    /// </summary>
    private sealed class SharedChallengeStore : IHttp01ChallengeStore
    {
        private readonly ConcurrentDictionary<string, string> _pending = new(StringComparer.Ordinal);
        private int _reads;

        public bool IsProcessLocal => false;

        public int Reads => Volatile.Read(ref _reads);

        public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken)
        {
            _pending[token] = keyAuthorization;
            return Task.CompletedTask;
        }

        public Task<string?> GetAsync(string token, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _reads);
            return Task.FromResult(_pending.TryGetValue(token, out string? value) ? value : null);
        }

        public Task RemoveAsync(string token, CancellationToken cancellationToken)
        {
            _pending.TryRemove(token, out _);
            return Task.CompletedTask;
        }
    }
}
