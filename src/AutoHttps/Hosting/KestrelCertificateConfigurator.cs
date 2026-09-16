using System;
using AutoHttps.Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

internal sealed class KestrelCertificateConfigurator : IConfigureOptions<KestrelServerOptions>
{
    private readonly AutoHttpsOptions _options;
    private readonly CertificateSelector _selector;
    private readonly KestrelConfigurationProbe _probe;

    public KestrelCertificateConfigurator(
        IOptions<AutoHttpsOptions> options,
        CertificateSelector selector,
        KestrelConfigurationProbe probe)
    {
        _options = options.Value;
        _selector = selector;
        _probe = probe;
    }

    public void Configure(KestrelServerOptions options)
    {
        if (!_options.ConfigureKestrel)
        {
            return;
        }

        // Capture whatever HTTPS defaults were configured before AutoHttps. ConfigureHttpsDefaults
        // replaces the single defaults delegate rather than adding to it, so without replaying the
        // previous one the application's own TLS options and certificate selector would be lost even
        // when AutoHttps runs last. If AutoHttps runs first this is the empty starting default. When
        // the previous delegate cannot be read (a future Kestrel change) it is not replayed, and the
        // startup guard still reports a selector that a later call replaced.
        Action<HttpsConnectionAdapterOptions>? previous = KestrelHttpsDefaults.Capture(options);
        var composer = new KestrelHttpsDefaultsComposer(_selector, previous, _probe);
        options.ConfigureHttpsDefaults(composer.Apply);
    }
}
