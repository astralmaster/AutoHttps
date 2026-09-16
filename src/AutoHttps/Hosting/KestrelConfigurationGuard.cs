using System;
using AutoHttps.Internal;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

/// <summary>
/// Reports the two ways HTTPS wiring can leave AutoHttps unable to serve a managed name, both caused by
/// Kestrel keeping only the last HTTPS-defaults delegate. A later ConfigureHttpsDefaults call replaces
/// the certificate selector: that is caught before Kestrel binds and fails startup. An endpoint
/// declared with UseHttps before AddAutoHttps keeps the earlier defaults, so the selector is never
/// consulted for it: the composer cannot run for such an endpoint, so a flag still unset once the host
/// has started reports it. Without either check the application fails with Kestrel's opaque "no server
/// certificate" error or, in Development, serves the ASP.NET Core development certificate for a managed
/// domain without a word. It runs only for the automatic Kestrel path
/// (<see cref="AutoHttpsOptions.ConfigureKestrel"/>).
/// </summary>
internal sealed class KestrelConfigurationGuard : IStartupFilter
{
    private readonly AutoHttpsOptions _options;
    private readonly IOptions<KestrelServerOptions> _kestrel;
    private readonly KestrelConfigurationProbe _probe;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<KestrelConfigurationGuard> _logger;

    public KestrelConfigurationGuard(
        IOptions<AutoHttpsOptions> options,
        IOptions<KestrelServerOptions> kestrel,
        KestrelConfigurationProbe probe,
        IHostApplicationLifetime lifetime,
        ILogger<KestrelConfigurationGuard> logger)
    {
        _options = options.Value;
        _kestrel = kestrel;
        _probe = probe;
        _lifetime = lifetime;
        _logger = logger;
    }

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        if (_options.ConfigureKestrel && DomainNormalizer.Normalize(_options.DomainNames).Count > 0)
        {
            VerifySelectorNotReplaced();

            // The composer runs only for endpoints configured after AutoHttps, so whether it ran at all
            // is not known until Kestrel has bound. Checking the flag reads no Kestrel internals, so it
            // still works when the reflection above cannot.
            _lifetime.ApplicationStarted.Register(WarnIfDefaultsNeverApplied);
        }

        return next;
    }

    private void VerifySelectorNotReplaced()
    {
        if (!KestrelHttpsDefaults.CanInspect)
        {
            Log.KestrelDefaultsUnverifiable(_logger);
            return;
        }

        // Resolving the value runs every IConfigureOptions<KestrelServerOptions>, so the delegate read
        // here is the final one. AutoHttps installs a KestrelHttpsDefaultsComposer; anything else means
        // a later ConfigureHttpsDefaults call replaced it.
        Action<HttpsConnectionAdapterOptions>? current = KestrelHttpsDefaults.Capture(_kestrel.Value);
        if (current is null || current.Target is KestrelHttpsDefaultsComposer)
        {
            return;
        }

        string domains = string.Join(", ", DomainNormalizer.Normalize(_options.DomainNames));
        throw new InvalidOperationException(
            "AutoHttps installed its certificate selector on Kestrel's HTTPS defaults, but a later " +
            "ConfigureHttpsDefaults call replaced it, so AutoHttps cannot serve certificates for " +
            $"{domains}. Call AddAutoHttps after your own ConfigureHttpsDefaults call, or set " +
            "AutoHttpsOptions.ConfigureKestrel to false and wire endpoints with listenOptions.UseAutoHttps " +
            "if you configure the HTTPS certificate yourself.");
    }

    private void WarnIfDefaultsNeverApplied()
    {
        if (_probe.Applied)
        {
            return;
        }

        Log.KestrelDefaultsNotApplied(_logger, string.Join(", ", DomainNormalizer.Normalize(_options.DomainNames)));
    }
}
