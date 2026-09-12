using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AutoHttps.Azure;

/// <summary>
/// Registers the Azure DNS challenge provider and the Key Vault stores with AutoHttps.
/// </summary>
public static class AutoHttpsAzureBuilderExtensions
{
    /// <summary>
    /// Answers <c>dns-01</c> challenges through Azure DNS. Every validated domain must be in the
    /// configured zone.
    /// </summary>
    /// <param name="builder">The AutoHttps builder.</param>
    /// <param name="configure">Configures the Azure DNS options.</param>
    /// <returns>The builder.</returns>
    public static IAutoHttpsBuilder UseAzureDns(this IAutoHttpsBuilder builder, Action<AzureDnsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.Configure(configure);

        builder.Services.TryAddSingleton<IAzureDnsClient>(provider =>
        {
            AzureDnsOptions options = provider.GetRequiredService<IOptions<AzureDnsOptions>>().Value;
            return new AzureDnsClientAdapter(options, AzureCredentials.Create(options.TenantId, options.ClientId, options.ClientSecret));
        });

        builder.Services.Replace(ServiceDescriptor.Singleton<IDnsChallengeProvider>(provider =>
            new AzureDnsChallengeProvider(
                provider.GetRequiredService<IAzureDnsClient>(),
                provider.GetRequiredService<IOptions<AzureDnsOptions>>())));

        return builder;
    }

    /// <summary>
    /// Keeps certificates and the ACME account key in Azure Key Vault instead of on the filesystem.
    /// </summary>
    /// <param name="builder">The AutoHttps builder.</param>
    /// <param name="configure">Configures the Key Vault options.</param>
    /// <returns>The builder.</returns>
    public static IAutoHttpsBuilder UseAzureKeyVault(this IAutoHttpsBuilder builder, Action<AzureKeyVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.Configure(configure);
        builder.Services.AddOptions<AzureKeyVaultOptions>().ValidateOnStart();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<AzureKeyVaultOptions>, AzureKeyVaultOptionsValidator>());

        builder.Services.TryAddSingleton<IKeyVaultSecretClient>(provider =>
        {
            AzureKeyVaultOptions options = provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>().Value;
            Uri vaultUri = options.VaultUri
                ?? throw new InvalidOperationException("AzureKeyVaultOptions.VaultUri is required.");

            return new KeyVaultSecretClientAdapter(vaultUri, AzureCredentials.Create(options.TenantId, options.ClientId, options.ClientSecret));
        });

        builder.Services.Replace(ServiceDescriptor.Singleton<ICertificateStore>(provider =>
            new KeyVaultCertificateStore(
                provider.GetRequiredService<IKeyVaultSecretClient>(),
                provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>())));

        builder.Services.Replace(ServiceDescriptor.Singleton<IAccountKeyStore>(provider =>
            new KeyVaultAccountKeyStore(
                provider.GetRequiredService<IKeyVaultSecretClient>(),
                provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>())));

        return builder;
    }
}
