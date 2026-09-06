using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AutoHttps.IntegrationTests;

internal enum KestrelIntegration
{
    HttpsDefaults,
    ListenOptions,
}

/// <summary>
/// An application under test: a real Kestrel host with AutoHttps wired in, listening on a plain
/// HTTP port for challenge responses and an HTTPS port that serves whatever certificate AutoHttps
/// has obtained.
/// </summary>
internal sealed class TestApplication : IAsyncDisposable
{
    // Kestrel aborts a handshake that takes longer than ten seconds. These tests assert which
    // certificate is served, not how quickly, and a machine running the whole suite at once takes
    // longer than that, which shows up as a dropped connection rather than as a slow one.
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(60);

    private readonly WebApplication _app;
    private readonly LogCapture _log;

    public LogCapture Log => _log;

    private TestApplication(WebApplication app, LogCapture log)
    {
        _app = app;
        _log = log;

        HttpPort = ReadPort(app, "http");
        HttpsPort = ReadPort(app, "https");
    }

    public int HttpPort { get; }

    public int HttpsPort { get; }

    public Uri HttpBaseAddress => new($"http://127.0.0.1:{HttpPort}/");

    public IServiceProvider Services => _app.Services;

    public static async Task<TestApplication> StartAsync(
        TestCertificateAuthority authority,
        Action<AutoHttpsOptions> configure,
        KestrelIntegration integration = KestrelIntegration.HttpsDefaults,
        Action<IServiceCollection>? configureServices = null,
        bool enableHttpsRedirection = false,
        bool manualChallengeMiddleware = false,
        bool tuneHandshakeTimeout = true,
        string environment = "Production",
        Action<IAutoHttpsBuilder>? configureBuilder = null)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Debug);

        var capture = new LogCapture();
        builder.Logging.AddProvider(capture);

        IAutoHttpsBuilder autoHttps = builder.Services.AddAutoHttps(options =>
        {
            options.CertificateAuthority = authority.DirectoryUri;
            options.EmailAddress = "operator@example.com";
            options.AcceptTermsOfService = true;
            options.PollInterval = TimeSpan.FromMilliseconds(100);
            options.ValidationTimeout = TimeSpan.FromSeconds(30);
            options.InitialRetryDelay = TimeSpan.FromMilliseconds(200);
            options.MaxRetryDelay = TimeSpan.FromSeconds(2);
            options.DnsPropagationDelay = TimeSpan.Zero;
            options.ConfigureKestrel = integration == KestrelIntegration.HttpsDefaults;
            configure(options);
        });

        configureBuilder?.Invoke(autoHttps);

        if (enableHttpsRedirection)
        {
            // The port is discovered from the server's bound addresses, which is only possible once
            // Kestrel has chosen one.
            builder.Services.AddHttpsRedirection(redirection =>
                redirection.RedirectStatusCode = Microsoft.AspNetCore.Http.StatusCodes.Status307TemporaryRedirect);
        }

        configureServices?.Invoke(builder.Services);

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(IPAddress.Loopback, 0);

            if (integration == KestrelIntegration.HttpsDefaults)
            {
                kestrel.Listen(IPAddress.Loopback, 0, listen =>
                    listen.UseHttps(https => https.HandshakeTimeout = HandshakeTimeout));
            }
            else
            {
                kestrel.Listen(IPAddress.Loopback, 0, listen =>
                {
                    if (tuneHandshakeTimeout)
                    {
                        listen.UseAutoHttps(kestrel.ApplicationServices, tls => tls.HandshakeTimeout = HandshakeTimeout);
                    }
                    else
                    {
                        listen.UseAutoHttps(kestrel.ApplicationServices);
                    }
                });
            }
        });

        WebApplication app = builder.Build();

        if (manualChallengeMiddleware)
        {
            app.UseAutoHttpsChallenges();
        }

        if (enableHttpsRedirection)
        {
            app.UseHttpsRedirection();
        }

        app.MapGet("/", () => "ok");

        await app.StartAsync();

        var instance = new TestApplication(app, capture);
        authority.HttpChallengeResolver = _ => instance.HttpBaseAddress;

        return instance;
    }

    private static int ReadPort(WebApplication app, string scheme)
    {
        foreach (string url in app.Urls)
        {
            var parsed = new Uri(url);
            if (string.Equals(parsed.Scheme, scheme, StringComparison.Ordinal))
            {
                return parsed.Port;
            }
        }

        throw new InvalidOperationException($"The test application did not bind a {scheme} endpoint.");
    }

    public Task StopAsync() => _app.StopAsync();

    public ValueTask DisposeAsync() => _app.DisposeAsync();

    public ServerCertificate? FindCertificate(string hostName) =>
        _app.Services.GetRequiredService<CertificateSelector>().Find(hostName);

    public async Task<ServerCertificate> WaitForCertificateAsync(string hostName, TimeSpan timeout)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (FindCertificate(hostName) is { } certificate)
            {
                return certificate;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException(
            $"No certificate for '{hostName}' was published within {timeout}.{Environment.NewLine}{_log.Describe()}");
    }

    public async Task<ServerCertificate> WaitForCertificateChangeAsync(string hostName, string previousThumbprint, TimeSpan timeout)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (FindCertificate(hostName) is { } certificate &&
                !string.Equals(certificate.Leaf.Thumbprint, previousThumbprint, StringComparison.Ordinal))
            {
                return certificate;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException(
            $"The certificate for '{hostName}' was not replaced within {timeout}.{Environment.NewLine}{_log.Describe()}");
    }

    /// <summary>
    /// Completes a real TLS handshake against the HTTPS endpoint and returns what the server sent.
    /// </summary>
    /// <param name="knownIntermediate">
    /// An intermediate the client already holds. Kestrel cannot send a chain while a certificate
    /// selector is in use, so a client reaching such an endpoint completes the chain from its own
    /// store or not at all. Windows does this silently, which is why leaving this null on that path
    /// passes there and fails everywhere else.
    /// </param>
    public async Task<TlsHandshakeResult> HandshakeAsync(
        string serverName,
        X509Certificate2? trustRoot = null,
        List<SslApplicationProtocol>? applicationProtocols = null,
        X509Certificate2? knownIntermediate = null)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, HttpsPort);

        X509Certificate2? leaf = null;
        var chainElements = new List<X509Certificate2>();
        X509ChainStatus[] chainStatus = [];

        using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, certificate, chain, _) =>
        {
            if (certificate is not null)
            {
                leaf = new X509Certificate2(certificate);
            }

            if (chain is not null)
            {
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    chainElements.Add(new X509Certificate2(element.Certificate));
                }

                chainStatus = chain.ChainStatus;
            }

            return true;
        });

        try
        {
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = serverName,
                ApplicationProtocols = applicationProtocols,
            });
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException)
        {
            // A closed connection tells the client nothing about why. The server's own log
            // separates "the selector had no certificate" from "the handshake timed out", and
            // those have opposite causes.
            throw new InvalidOperationException(
                $"The TLS handshake for '{serverName}' failed: {ex.Message}" + Environment.NewLine +
                _log.Describe(),
                ex);
        }

        if (leaf is null)
        {
            throw new InvalidOperationException("The server did not present a certificate.");
        }

        bool trusted = trustRoot is null || Validate(leaf, chainElements, trustRoot, knownIntermediate);
        return new TlsHandshakeResult(leaf, chainElements, chainStatus, trusted, stream.NegotiatedApplicationProtocol);
    }

    /// <summary>Sends a plain HTTP request, used to check the challenge responder directly.</summary>
    public async Task<(HttpStatusCode Status, string Body)> GetAsync(string path)
    {
        using var handler = new System.Net.Http.HttpClientHandler { AllowAutoRedirect = false };
        using var client = new System.Net.Http.HttpClient(handler) { BaseAddress = HttpBaseAddress };
        using System.Net.Http.HttpResponseMessage response = await client.GetAsync(path);
        return (response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    private static bool Validate(
        X509Certificate2 leaf,
        IReadOnlyList<X509Certificate2> presented,
        X509Certificate2 trustRoot,
        X509Certificate2? knownIntermediate)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(trustRoot);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        foreach (X509Certificate2 certificate in presented)
        {
            chain.ChainPolicy.ExtraStore.Add(certificate);
        }

        if (knownIntermediate is not null)
        {
            chain.ChainPolicy.ExtraStore.Add(knownIntermediate);
        }

        return chain.Build(leaf);
    }

}

internal sealed record TlsHandshakeResult(
    X509Certificate2 Leaf,
    IReadOnlyList<X509Certificate2> PresentedChain,
    X509ChainStatus[] ChainStatus,
    bool ChainIsTrusted,
    SslApplicationProtocol NegotiatedProtocol);
