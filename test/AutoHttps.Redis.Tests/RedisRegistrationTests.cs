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
