using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AutoHttps.PebbleTests;

/// <summary>
/// A Kestrel application configured exactly as a real deployment would be, except that it points at
/// Pebble instead of Let's Encrypt. It binds the challenge port on every interface so that Pebble,
/// running in a container, can reach it.
/// </summary>
internal sealed class PebbleApplication : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly LogCapture _log;

    private PebbleApplication(WebApplication app, LogCapture log)
    {
        _app = app;
        _log = log;

        HttpsPort = app.Urls
            .Select(url => new Uri(url))
            .Where(url => url.Scheme == Uri.UriSchemeHttps)
            .Select(url => url.Port)
            .FirstOrDefault();
    }

    public int HttpsPort { get; }

    public LogCapture Log => _log;

    public static async Task<PebbleApplication> StartAsync(PebbleFixture pebble, Action<AutoHttpsOptions> configure)
    {
        // Pebble validates challenges on one fixed port, so every application in this suite competes
        // for it. Waiting for the previous test's listener to go away keeps that from looking like a
        // product failure.
        await WaitForChallengePortAsync();

        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Debug);

        var capture = new LogCapture();
        builder.Logging.AddProvider(capture);

        builder.Services.AddAutoHttps(options =>
        {
            options.CertificateAuthority = pebble.DirectoryUri;
            options.EmailAddress = "operator@example.com";
            options.AcceptTermsOfService = true;
            options.PollInterval = TimeSpan.FromMilliseconds(250);
            options.ValidationTimeout = TimeSpan.FromSeconds(60);
            options.InitialRetryDelay = TimeSpan.FromSeconds(1);
            options.MaxRetryDelay = TimeSpan.FromSeconds(5);
            options.DnsPropagationDelay = TimeSpan.Zero;
            options.ConfigureKestrel = false;
            configure(options);
        });

        // Pebble serves its API over HTTPS with a private root. Reconfiguring the named client is
        // the supported way to do that, so this doubles as a test of that extension point.
        builder.Services.AddHttpClient(AutoHttpsDefaults.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(pebble.CreateAcmeHandler);

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(IPAddress.Any, PebbleFixture.HttpChallengePort);
            kestrel.Listen(IPAddress.Loopback, 0, listen => listen.UseAutoHttps(
                kestrel.ApplicationServices,
                tls => tls.HandshakeTimeout = TimeSpan.FromSeconds(60)));
        });

        WebApplication app = builder.Build();
        app.MapGet("/", () => "ok");

        await app.StartAsync();
        await AssertWeOwnTheChallengePortAsync();

        return new PebbleApplication(app, capture);
    }

    /// <summary>
    /// The challenge port is fixed and shared, so another process holding it would show up as an
    /// unexplained validation timeout. Checking directly turns that into an immediate, clear error.
    /// </summary>
    private static async Task AssertWeOwnTheChallengePortAsync()
    {
        using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        string body = await client.GetStringAsync(new Uri($"http://127.0.0.1:{PebbleFixture.HttpChallengePort}/"));

        if (body != "ok")
        {
            throw new InvalidOperationException(
                $"Port {PebbleFixture.HttpChallengePort} is answering \"{body}\" rather than this test's application. " +
                "Something else on this machine is holding the challenge port.");
        }
    }

    private static async Task WaitForChallengePortAsync()
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(30);

        while (true)
        {
            try
            {
                var probe = new TcpListener(IPAddress.Any, PebbleFixture.HttpChallengePort);
                probe.Start();
                probe.Stop();

                return;
            }
            catch (SocketException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(200);
            }
        }
    }

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

            await Task.Delay(100);
        }

        throw new TimeoutException(
            $"Pebble did not issue a certificate for '{hostName}' within {timeout}.{Environment.NewLine}{_log.Describe()}");
    }

    public async Task<ServerCertificate> WaitForCertificateChangeAsync(string hostName, string previous, TimeSpan timeout)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (FindCertificate(hostName) is { } certificate &&
                !string.Equals(certificate.Leaf.Thumbprint, previous, StringComparison.Ordinal))
            {
                return certificate;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException(
            $"Pebble did not replace the certificate for '{hostName}' within {timeout}.{Environment.NewLine}{_log.Describe()}");
    }

    /// <summary>Completes a real TLS handshake and validates the chain against Pebble's root.</summary>
    public async Task<bool> HandshakeIsTrustedAsync(string serverName, X509Certificate2 root)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, HttpsPort);

        X509Certificate2? leaf = null;
        var presented = new List<X509Certificate2>();

        using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, certificate, chain, _) =>
        {
            if (certificate is not null)
            {
                leaf = new X509Certificate2(certificate);
            }

            if (chain is not null)
            {
                presented.AddRange(chain.ChainElements.Select(e => new X509Certificate2(e.Certificate)));
            }

            return true;
        });

        await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = serverName });

        if (leaf is null)
        {
            return false;
        }

        using var validation = new X509Chain();
        validation.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        validation.ChainPolicy.CustomTrustStore.Add(root);
        validation.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        foreach (X509Certificate2 certificate in presented)
        {
            validation.ChainPolicy.ExtraStore.Add(certificate);
        }

        return validation.Build(leaf);
    }
}

internal sealed class LogCapture : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _entries = new();
    private readonly ConcurrentDictionary<int, int> _counts = new();

    public ILogger CreateLogger(string categoryName) => new Capturing(categoryName, this);

    public int CountOf(int eventId) => _counts.TryGetValue(eventId, out int count) ? count : 0;

    public IReadOnlyList<string> Entries => _entries.ToArray();

    public string Describe(int limit = 40) => string.Join(Environment.NewLine, _entries.Reverse().Take(limit).Reverse());

    public void Dispose()
    {
    }

    private void Record(string entry, int eventId)
    {
        _entries.Enqueue(entry);
        _counts.AddOrUpdate(eventId, 1, static (_, existing) => existing + 1);

        while (_entries.Count > 400 && _entries.TryDequeue(out _))
        {
        }
    }

    private sealed class Capturing : ILogger
    {
        private readonly string _category;
        private readonly LogCapture _owner;

        public Capturing(string category, LogCapture owner)
        {
            _category = category;
            _owner = owner;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            string message = $"{logLevel} {_category}[{eventId.Id}] {formatter(state, exception)}";
            if (exception is not null)
            {
                message += Environment.NewLine + "    " + exception.GetType().Name + ": " + exception.Message;
            }

            _owner.Record(message, eventId.Id);
        }
    }
}
