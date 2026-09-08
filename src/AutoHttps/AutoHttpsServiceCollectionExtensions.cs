using System;
using System.IO;
using System.Reflection;
using AutoHttps.Certificates;
using AutoHttps.Challenges;
using AutoHttps.Hosting;
using AutoHttps.Internal;
using AutoHttps.Renewal;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AutoHttps;

/// <summary>
/// Registers AutoHttps with an application's service collection.
/// </summary>
public static class AutoHttpsServiceCollectionExtensions
{
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(60);

    // A DNS-over-HTTPS lookup that has not answered in a few seconds is treated as a miss and retried
    // on the next poll, so the per-request timeout is kept well under the propagation timeout.
    private static readonly TimeSpan DnsQueryTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Adds the services that obtain and renew certificates, and attaches the certificate selector
    /// to Kestrel's HTTPS defaults.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configures the options.</param>
    /// <returns>A builder for replacing the storage, locking and DNS components.</returns>
    public static IAutoHttpsBuilder AddAutoHttps(this IServiceCollection services, Action<AutoHttpsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        return services.AddAutoHttpsCore();
    }

    /// <summary>
    /// Adds the services that obtain and renew certificates, binding options from configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration section holding the options.</param>
    /// <returns>A builder for replacing the storage, locking and DNS components.</returns>
    public static IAutoHttpsBuilder AddAutoHttps(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<AutoHttpsOptions>(configuration.Bind);
        return services.AddAutoHttpsCore();
    }

    private static AutoHttpsBuilder AddAutoHttpsCore(this IServiceCollection services)
    {
        services.AddOptions<AutoHttpsOptions>().ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AutoHttpsOptions>, AutoHttpsOptionsValidator>());

        services.TryAddSingleton(TimeProvider.System);

        services.AddHttpClient(AutoHttpsDefaults.HttpClientName, static client =>
        {
            client.Timeout = HttpTimeout;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        });

        services.AddHttpClient(AutoHttpsDefaults.DnsHttpClientName, static client =>
        {
            client.Timeout = DnsQueryTimeout;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        });

        services.TryAddSingleton<DnsPropagationChecker>();

        services.TryAddSingleton<FileSystemStore>(static provider => new FileSystemStore(ResolveStorageDirectory(provider)));
        services.TryAddSingleton<ICertificateStore>(static provider => provider.GetRequiredService<FileSystemStore>());
        services.TryAddSingleton<IAccountKeyStore>(static provider => provider.GetRequiredService<FileSystemStore>());
        services.TryAddSingleton<IDistributedLock>(static provider => new FileSystemLock(ResolveStorageDirectory(provider)));

        services.TryAddSingleton<CertificateSelector>();
        services.TryAddSingleton<Http01ChallengeStore>();
        services.TryAddSingleton<AcmeSession>();
        services.TryAddSingleton<CertificateAcquirer>();

        // The instruments are inert until something subscribes, so registering AddMetrics only
        // guarantees the IMeterFactory the meter needs is present even under a slim host builder.
        services.AddMetrics();
        services.TryAddSingleton<AutoHttpsState>();
        services.TryAddSingleton<AutoHttpsMetrics>();
        services.TryAddSingleton<CertificateEventPublisher>();
        services.TryAddSingleton<IAutoHttpsCertificateInspector, AutoHttpsCertificateInspector>();
        services.TryAddSingleton<IAutoHttpsCertificateManager, AutoHttpsCertificateManager>();

        // Replaced by UseDevelopmentCertificate; disabled unless that is called.
        services.TryAddSingleton(DevelopmentCertificateSource.Disabled);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IChallengeHandler, Http01ChallengeHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IChallengeHandler, Dns01ChallengeHandler>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStartupFilter, Http01StartupFilter>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IConfigureOptions<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>, KestrelCertificateConfigurator>());

        services.AddHostedService<AutoHttpsService>();

        return new AutoHttpsBuilder(services);
    }

    private static string ResolveStorageDirectory(IServiceProvider provider)
    {
        AutoHttpsOptions options = provider.GetRequiredService<IOptions<AutoHttpsOptions>>().Value;
        return ResolveStorageDirectory(options);
    }

    internal static string ResolveStorageDirectory(AutoHttpsOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.StorageDirectory))
        {
            return options.StorageDirectory;
        }

        string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(root))
        {
            root = AppContext.BaseDirectory;
        }

        return Path.Combine(root, "autohttps");
    }

    private static string UserAgent { get; } = BuildUserAgent();

    private static string BuildUserAgent()
    {
        string version = typeof(AutoHttpsServiceCollectionExtensions).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";

        int metadata = version.IndexOf('+', StringComparison.Ordinal);
        if (metadata >= 0)
        {
            version = version[..metadata];
        }

        return $"AutoHttps/{version} (+https://github.com/astralmaster/AutoHttps)";
    }
}
