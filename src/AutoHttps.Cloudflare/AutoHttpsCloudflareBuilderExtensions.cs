using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AutoHttps.Cloudflare;

/// <summary>
/// Registers the Cloudflare DNS challenge provider with AutoHttps.
/// </summary>
public static class AutoHttpsCloudflareBuilderExtensions
{
    /// <summary>
    /// Answers <c>dns-01</c> challenges through Cloudflare, using an API token.
    /// </summary>
    /// <param name="builder">The AutoHttps builder.</param>
    /// <param name="apiToken">A Cloudflare API token with the Zone.DNS Edit permission.</param>
    /// <returns>The builder.</returns>
    public static IAutoHttpsBuilder UseCloudflareDns(this IAutoHttpsBuilder builder, string apiToken) =>
        builder.UseCloudflareDns(options => options.ApiToken = apiToken);

    /// <summary>
    /// Answers <c>dns-01</c> challenges through Cloudflare, configured with a callback.
    /// </summary>
    /// <param name="builder">The AutoHttps builder.</param>
    /// <param name="configure">Configures the Cloudflare options.</param>
    /// <returns>The builder.</returns>
    public static IAutoHttpsBuilder UseCloudflareDns(this IAutoHttpsBuilder builder, Action<CloudflareDnsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.Configure(configure);
        builder.Services.AddHttpClient(CloudflareDnsChallengeProvider.HttpClientName, client =>
            client.Timeout = TimeSpan.FromSeconds(30));
        builder.Services.Replace(ServiceDescriptor.Singleton<IDnsChallengeProvider, CloudflareDnsChallengeProvider>());

        return builder;
    }
}
