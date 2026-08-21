using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.IntegrationTests;

public class ResilienceTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task ALockThatKeepsThrowingDoesNotStopTheApplication()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureServices: services =>
                services.Replace(ServiceDescriptor.Singleton<IDistributedLock, ThrowingLock>()));

        await Task.Delay(TimeSpan.FromSeconds(3));

        // The certificate never arrives, but the host is still up and still serving.
        (HttpStatusCode status, string body) = await app.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("ok", body);
        Assert.Null(app.FindCertificate("app.example.com"));
    }

    [Fact]
    public async Task AStoreThatCannotSaveStillLeavesTheCertificateInUse()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureServices: services =>
                services.Replace(ServiceDescriptor.Singleton<ICertificateStore, UnwritableStore>()));

        ServerCertificate certificate = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        TlsHandshakeResult handshake = await app.HandshakeAsync(
            "app.example.com", authority.RootCertificate, knownIntermediate: authority.IntermediateCertificate);
        Assert.Equal(certificate.Leaf.Thumbprint, handshake.Leaf.Thumbprint);
        Assert.True(handshake.ChainIsTrusted);
    }

    [Fact]
    public async Task AStoreThatCannotBeReadFallsBackToOrderingAFreshCertificate()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureServices: services =>
                services.Replace(ServiceDescriptor.Singleton<ICertificateStore, UnreadableStore>()));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
    }

    [Fact]
    public async Task TheFallbackCertificateIsReportedOnceRatherThanOnEveryHandshake()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.FailValidation = true;

        var log = new CountingLoggerProvider();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureServices: services => services.AddSingleton<ILoggerProvider>(log));

        for (int i = 0; i < 5; i++)
        {
            await app.HandshakeAsync("app.example.com");
        }

        // A warning per TLS handshake would drown out everything else in a busy log.
        Assert.Equal(1, log.CountOf(112));
    }

    [Fact]
    public void AnIncompleteConfigurationIsRejectedBeforeTheApplicationEverStarts()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(System.Net.IPAddress.Loopback, 0));

        builder.Services.AddAutoHttps(options => options.DomainNames.Add("example.com"));

        // Attaching to Kestrel forces the options to be read while the host is being constructed, so
        // a misconfigured application fails before it binds a port, and reports every problem at once.
        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(() => builder.Build());

        Assert.Contains(exception.Failures, f => f.Contains("EmailAddress", StringComparison.Ordinal));
        Assert.Contains(exception.Failures, f => f.Contains("AcceptTermsOfService", StringComparison.Ordinal));
    }

    [Fact]
    public void AnInvalidDomainIsRejectedWithTheOffendingValueInTheMessage()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(System.Net.IPAddress.Loopback, 0));

        builder.Services.AddAutoHttps(options =>
        {
            options.DomainNames.Add("https://example.com/app");
            options.EmailAddress = "operator@example.com";
            options.AcceptTermsOfService = true;
        });

        OptionsValidationException exception = Assert.Throws<OptionsValidationException>(() => builder.Build());

        Assert.Contains(exception.Failures, f => f.Contains("https://example.com/app", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheBuilderReplacesTheDefaultComponents()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(System.Net.IPAddress.Loopback, 0));

        builder.Services
            .AddAutoHttps(options =>
            {
                options.DomainNames.Add("example.com");
                options.EmailAddress = "operator@example.com";
                options.AcceptTermsOfService = true;
                options.PreferredChallengeType = "dns-01";
            })
            .PersistCertificatesTo<UnwritableStore>()
            .UseDistributedLock<ThrowingLock>()
            .UseDnsChallengeProvider<NoopDnsProvider>();

        await using WebApplication app = builder.Build();
        await app.StartAsync();

        Assert.IsType<UnwritableStore>(app.Services.GetRequiredService<ICertificateStore>());
        Assert.IsType<ThrowingLock>(app.Services.GetRequiredService<IDistributedLock>());
        Assert.IsType<NoopDnsProvider>(app.Services.GetRequiredService<IDnsChallengeProvider>());

        await app.StopAsync();
    }

    private sealed class ThrowingLock : IDistributedLock
    {
        public Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken) =>
            throw new UnauthorizedAccessException("The lock directory is not writable.");
    }

    private sealed class UnwritableStore : ICertificateStore
    {
        public Task<CertificateMaterial?> LoadAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult<CertificateMaterial?>(null);

        public Task SaveAsync(string name, CertificateMaterial material, CancellationToken cancellationToken) =>
            throw new System.IO.IOException("The volume is read only.");
    }

    private sealed class UnreadableStore : ICertificateStore
    {
        public Task<CertificateMaterial?> LoadAsync(string name, CancellationToken cancellationToken) =>
            throw new System.IO.IOException("The volume disappeared.");

        public Task SaveAsync(string name, CertificateMaterial material, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class NoopDnsProvider : IDnsChallengeProvider
    {
        public Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class CountingLoggerProvider : ILoggerProvider
    {
        private readonly System.Collections.Concurrent.ConcurrentDictionary<int, int> _counts = new();

        public ILogger CreateLogger(string categoryName) => new CountingLogger(_counts);

        public int CountOf(int eventId) => _counts.TryGetValue(eventId, out int count) ? count : 0;

        public void Dispose()
        {
        }

        private sealed class CountingLogger : ILogger
        {
            private readonly System.Collections.Concurrent.ConcurrentDictionary<int, int> _counts;

            public CountingLogger(System.Collections.Concurrent.ConcurrentDictionary<int, int> counts) => _counts = counts;

            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                _counts.AddOrUpdate(eventId.Id, 1, static (_, existing) => existing + 1);
        }
    }
}
