using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AutoHttps.Redis.Tests;

/// <summary>
/// The stores are only useful if <c>UseRedis</c> actually puts them in the container, so this checks the
/// wiring rather than the implementations. No Redis connection is needed: nothing here resolves a
/// service, it inspects what was registered.
/// </summary>
public sealed class RedisRegistrationTests
{
    [Fact]
    public void UseRedisSharesTheChallengeAnswersAsWellAsTheCertificateAndAccountKey()
    {
        IAutoHttpsBuilder builder = Configured();

        Assert.Equal(typeof(RedisCertificateStore), Registered<ICertificateStore>(builder));
        Assert.Equal(typeof(RedisAccountKeyStore), Registered<IAccountKeyStore>(builder));
        Assert.Equal(typeof(RedisHttp01ChallengeStore), Registered<IHttp01ChallengeStore>(builder));
    }

    [Fact]
    public async Task TheStoresCanBeBuiltWhileRedisIsDown()
    {
        // The connection is made while the host builds its services. Throwing there would stop the
        // application from starting at all whenever Redis is briefly unavailable, as during a deploy.
        ServiceProvider services = new ServiceCollection()
            .AddLogging()
            .AddAutoHttps(options =>
            {
                options.DomainNames.Add("app.example.com");
                options.EmailAddress = "operator@example.com";
                options.AcceptTermsOfService = true;
            })
            .UseRedis("127.0.0.1:1,connectTimeout=500")
            .Services
            .BuildServiceProvider();

        await using (services)
        {
            ICertificateStore store = services.GetRequiredService<ICertificateStore>();
            Assert.False(services.GetRequiredService<StackExchange.Redis.IConnectionMultiplexer>().IsConnected);

            // Using the store fails, which AutoHttps treats as a failed attempt and retries.
            await Assert.ThrowsAnyAsync<Exception>(() => store.LoadAsync("anything", CancellationToken.None));
        }
    }

    [Theory]
    [InlineData("localhost:6379", false)]
    [InlineData("localhost:6379,abortConnect=true", true)]
    [InlineData("localhost:6379,AbortConnect=false", false)]
    public void AnExplicitAbortConnectIsLeftAsConfigured(string configuration, bool expected) =>
        Assert.Equal(expected, AutoHttpsRedisBuilderExtensions.CreateConfiguration(configuration).AbortOnConnectFail);

    [Fact]
    public void UseRedisCoordinatesInstancesThroughTheSameRedis()
    {
        // Sharing the certificate without sharing the lock is what made every replica order at once.
        Assert.Equal(typeof(RedisDistributedLock), Registered<IDistributedLock>(Configured()));
    }

    [Fact]
    public void ALockOfYourOwnCanBeKeptByRegisteringItAfterwards()
    {
        IAutoHttpsBuilder builder = Configured().UseDistributedLock<OwnLock>();

        Assert.Equal(typeof(OwnLock), Registered<IDistributedLock>(builder));
    }

    [Fact]
    public void TheChallengeStoreCanBeKeptOutOfRedisAfterwards()
    {
        // Redis for certificates but not for challenges, for a deployment that already routes the
        // challenge path to a single replica.
        IAutoHttpsBuilder builder = Configured().UseHttp01ChallengeStore<InProcessStore>();

        Assert.Equal(typeof(RedisCertificateStore), Registered<ICertificateStore>(builder));
        Assert.Equal(typeof(InProcessStore), Registered<IHttp01ChallengeStore>(builder));
    }

    private static IAutoHttpsBuilder Configured() =>
        new ServiceCollection()
            .AddAutoHttps(options =>
            {
                options.DomainNames.Add("app.example.com");
                options.EmailAddress = "operator@example.com";
                options.AcceptTermsOfService = true;
            })
            .UseRedis("localhost:6379");

    private static Type? Registered<TService>(IAutoHttpsBuilder builder) =>
        Assert.Single(builder.Services, descriptor => descriptor.ServiceType == typeof(TService)).ImplementationType;

    private sealed class OwnLock : IDistributedLock
    {
        public Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult<IAsyncDisposable?>(null);
    }

    private sealed class InProcessStore : IHttp01ChallengeStore
    {
        public bool IsProcessLocal => true;

        public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> GetAsync(string token, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task RemoveAsync(string token, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
