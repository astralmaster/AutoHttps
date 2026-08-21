using System;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

internal sealed class KestrelCertificateConfigurator : IConfigureOptions<KestrelServerOptions>
{
    private readonly AutoHttpsOptions _options;
    private readonly CertificateSelector _selector;

    public KestrelCertificateConfigurator(IOptions<AutoHttpsOptions> options, CertificateSelector selector)
    {
        _options = options.Value;
        _selector = selector;
    }

    public void Configure(KestrelServerOptions options)
    {
        if (!_options.ConfigureKestrel)
        {
            return;
        }

        options.ConfigureHttpsDefaults(https =>
        {
            // Kestrel ignores a configured certificate as soon as a selector is present, so simply
            // installing one would take over every endpoint and drop connections for names AutoHttps
            // does not manage. Whatever the application had is kept as the fallback instead. The
            // certificate is read inside the callback because endpoint configuration runs after
            // these defaults have been applied.
            Func<ConnectionContext?, string?, X509Certificate2?>? existing = https.ServerCertificateSelector;

            https.ServerCertificateSelector = (connection, name) =>
            {
                if (!string.IsNullOrEmpty(name) && _selector.Select(connection, name) is { } managed)
                {
                    return managed;
                }

                // A request for a name AutoHttps was not asked to manage, or one carrying no server
                // name at all, belongs to whatever the application configured. Only when the
                // application configured nothing does AutoHttps answer it.
                return existing?.Invoke(connection, name)
                    ?? https.ServerCertificate
                    ?? _selector.Select(connection, name);
            };
        });
    }
}
