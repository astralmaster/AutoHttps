using System;
using AutoHttps.Internal;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

/// <summary>
/// Fails startup with a clear message when a later ConfigureHttpsDefaults call has replaced the
/// certificate selector AutoHttps installed. Kestrel keeps only the last HTTPS-defaults delegate, so
/// declaring HTTPS configuration after AddAutoHttps drops the selector; the application then either
/// fails with Kestrel's opaque "no server certificate" error or, in Development, serves the ASP.NET
/// Core development certificate for a managed domain without a word. This surfaces the cause before
/// Kestrel binds. It runs only for the automatic Kestrel path (<see cref="AutoHttpsOptions.ConfigureKestrel"/>).
/// </summary>
internal sealed class KestrelConfigurationGuard : IStartupFilter
{
    private readonly AutoHttpsOptions _options;
    private readonly IOptions<KestrelServerOptions> _kestrel;
    private readonly ILogger<KestrelConfigurationGuard> _logger;

    public KestrelConfigurationGuard(
        IOptions<AutoHttpsOptions> options,
        IOptions<KestrelServerOptions> kestrel,
        ILogger<KestrelConfigurationGuard> logger)
    {
        _options = options.Value;
        _kestrel = kestrel;
        _logger = logger;
    }

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        Verify();
        return next;
    }

    private void Verify()
    {
        if (!_options.ConfigureKestrel || DomainNormalizer.Normalize(_options.DomainNames).Count == 0)
        {
            return;
        }

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
}
