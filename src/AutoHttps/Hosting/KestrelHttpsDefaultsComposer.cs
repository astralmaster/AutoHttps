using System;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace AutoHttps.Hosting;

/// <summary>
/// Reads back the HTTPS defaults Kestrel already holds. ConfigureHttpsDefaults keeps only the last
/// delegate and offers no getter, so a delegate installed before AutoHttps is reachable only by
/// reflection. When the member cannot be read, for example after a future Kestrel change,
/// <see cref="Capture"/> returns null and callers keep the older behaviour of not replaying it.
/// </summary>
internal static class KestrelHttpsDefaults
{
    private static readonly PropertyInfo? Property =
        typeof(KestrelServerOptions).GetProperty("HttpsDefaults", BindingFlags.Instance | BindingFlags.NonPublic);

    public static bool CanInspect => Property is not null;

    public static Action<HttpsConnectionAdapterOptions>? Capture(KestrelServerOptions options) =>
        Property?.GetValue(options) as Action<HttpsConnectionAdapterOptions>;
}

/// <summary>
/// Records whether Kestrel applied the HTTPS defaults AutoHttps installed. An endpoint declared with
/// UseHttps before AddAutoHttps copies whatever defaults existed at that moment, so the composer is
/// never invoked for it. A flag still unset once the host has started is how that ordering is caught,
/// without reading any Kestrel internals.
/// </summary>
internal sealed class KestrelConfigurationProbe
{
    private volatile bool _applied;

    public void MarkApplied() => _applied = true;

    public bool Applied => _applied;
}

/// <summary>
/// The HTTPS defaults AutoHttps installs. It replays whatever defaults were configured before it, so
/// the application's TLS options, certificate and selector survive, and then answers a name AutoHttps
/// manages from its own store while leaving every other name to the application. It is a named type
/// so <see cref="KestrelConfigurationGuard"/> can tell whether a later ConfigureHttpsDefaults call
/// replaced it.
/// </summary>
internal sealed class KestrelHttpsDefaultsComposer
{
    private readonly CertificateSelector _selector;
    private readonly Action<HttpsConnectionAdapterOptions>? _previous;
    private readonly KestrelConfigurationProbe _probe;

    public KestrelHttpsDefaultsComposer(
        CertificateSelector selector,
        Action<HttpsConnectionAdapterOptions>? previous,
        KestrelConfigurationProbe probe)
    {
        _selector = selector;
        _previous = previous;
        _probe = probe;
    }

    public void Apply(HttpsConnectionAdapterOptions https)
    {
        // Kestrel reached the composed defaults, so at least one HTTPS endpoint was configured after
        // AutoHttps installed them. The guard reads this after startup to catch the opposite ordering.
        _probe.MarkApplied();

        // Re-apply the defaults configured before AutoHttps. ConfigureHttpsDefaults would otherwise
        // have discarded them, because Kestrel keeps only the last delegate.
        _previous?.Invoke(https);

        Func<ConnectionContext?, string?, X509Certificate2?>? existing = https.ServerCertificateSelector;

        https.ServerCertificateSelector = (connection, name) =>
        {
            if (!string.IsNullOrEmpty(name) && _selector.Select(connection, name) is { } managed)
            {
                return managed;
            }

            // A name AutoHttps was not asked to manage, or a request carrying none, belongs to
            // whatever the application configured. AutoHttps answers it only when nothing else does.
            return existing?.Invoke(connection, name)
                ?? https.ServerCertificate
                ?? _selector.Select(connection, name);
        };
    }
}
