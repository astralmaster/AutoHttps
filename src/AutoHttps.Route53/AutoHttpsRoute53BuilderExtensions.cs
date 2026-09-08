using System;
using Amazon;
using Amazon.Route53;
using Amazon.Runtime;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AutoHttps.Route53;

/// <summary>
/// Registers the Route 53 DNS challenge provider with AutoHttps.
/// </summary>
public static class AutoHttpsRoute53BuilderExtensions
{
    /// <summary>
    /// Answers <c>dns-01</c> challenges through AWS Route 53. Credentials and region follow the AWS
    /// SDK's usual resolution unless set on the options.
    /// </summary>
    /// <param name="builder">The AutoHttps builder.</param>
    /// <param name="configure">Optionally configures the Route 53 options.</param>
    /// <returns>The builder.</returns>
    public static IAutoHttpsBuilder UseRoute53(this IAutoHttpsBuilder builder, Action<Route53DnsOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        builder.Services.TryAddSingleton<IRoute53Client>(provider =>
        {
            Route53DnsOptions options = provider.GetRequiredService<IOptions<Route53DnsOptions>>().Value;
            return new Route53ClientAdapter(CreateClient(options));
        });

        builder.Services.Replace(ServiceDescriptor.Singleton<IDnsChallengeProvider>(provider =>
            new Route53DnsChallengeProvider(
                provider.GetRequiredService<IRoute53Client>(),
                provider.GetRequiredService<IOptions<Route53DnsOptions>>())));

        return builder;
    }

    private static AmazonRoute53Client CreateClient(Route53DnsOptions options)
    {
        var config = new AmazonRoute53Config();
        if (!string.IsNullOrWhiteSpace(options.Region))
        {
            config.RegionEndpoint = RegionEndpoint.GetBySystemName(options.Region);
        }

        if (!string.IsNullOrWhiteSpace(options.AccessKeyId) && !string.IsNullOrWhiteSpace(options.SecretAccessKey))
        {
            return new AmazonRoute53Client(new BasicAWSCredentials(options.AccessKeyId, options.SecretAccessKey), config);
        }

        return new AmazonRoute53Client(config);
    }
}
