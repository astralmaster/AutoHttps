using System;
using System.Net.Security;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;

namespace AutoHttps;

/// <summary>
/// Wires AutoHttps into individual Kestrel endpoints.
/// </summary>
public static class ListenOptionsExtensions
{
    /// <summary>
    /// Serves AutoHttps certificates on this endpoint, sending the full chain the certificate
    /// authority issued.
    /// </summary>
    /// <param name="listenOptions">The endpoint to configure.</param>
    /// <param name="services">The application's service provider.</param>
    /// <returns>The endpoint, for chaining.</returns>
    /// <remarks>
    /// Prefer this over the automatic Kestrel wiring when a client needs the issuing intermediate
    /// certificates to be presented during the handshake. Kestrel ignores a configured chain when a
    /// certificate selector is in use, so the selector can only present the leaf.
    /// </remarks>
    public static ListenOptions UseAutoHttps(this ListenOptions listenOptions, IServiceProvider services) =>
        listenOptions.UseAutoHttps(services, configure: null);

    /// <summary>
    /// Serves AutoHttps certificates on this endpoint, sending the full chain the certificate
    /// authority issued, and configures the rest of the endpoint's TLS settings.
    /// </summary>
    /// <param name="listenOptions">The endpoint to configure.</param>
    /// <param name="services">The application's service provider.</param>
    /// <param name="configure">Adjusts the handshake options, for example the handshake timeout.</param>
    /// <returns>The endpoint, for chaining.</returns>
    /// <remarks>
    /// This endpoint is configured from a handshake callback, which Kestrel keeps separate from
    /// <c>ConfigureHttpsDefaults</c>. Settings applied there do not reach it, so anything this
    /// endpoint needs beyond the certificate has to be set here.
    /// </remarks>
    public static ListenOptions UseAutoHttps(
        this ListenOptions listenOptions,
        IServiceProvider services,
        Action<TlsHandshakeCallbackOptions>? configure)
    {
        ArgumentNullException.ThrowIfNull(listenOptions);
        ArgumentNullException.ThrowIfNull(services);

        CertificateSelector selector = services.GetRequiredService<CertificateSelector>();

        var options = new TlsHandshakeCallbackOptions
        {
            OnConnection = context => ValueTask.FromResult(CreateOptions(selector, context.ClientHelloInfo.ServerName)),
        };

        configure?.Invoke(options);

        return listenOptions.UseHttps(options);
    }

    /// <summary>
    /// Serves AutoHttps certificates on an endpoint configured through
    /// <see cref="HttpsConnectionAdapterOptions"/>.
    /// </summary>
    /// <param name="httpsOptions">The HTTPS options to configure.</param>
    /// <param name="services">The application's service provider.</param>
    /// <returns>The options, for chaining.</returns>
    public static HttpsConnectionAdapterOptions UseAutoHttps(
        this HttpsConnectionAdapterOptions httpsOptions,
        IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(httpsOptions);
        ArgumentNullException.ThrowIfNull(services);

        CertificateSelector selector = services.GetRequiredService<CertificateSelector>();
        httpsOptions.ServerCertificateSelector = selector.Select;

        return httpsOptions;
    }

    private static SslServerAuthenticationOptions CreateOptions(CertificateSelector selector, string? serverName)
    {
        ServerCertificate? certificate = selector.Find(serverName);

        if (certificate?.Context is { } context)
        {
            return new SslServerAuthenticationOptions { ServerCertificateContext = context };
        }

        return new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate?.Leaf ?? selector.Select(connection: null, serverName),
        };
    }
}
