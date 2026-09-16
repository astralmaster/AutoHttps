using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// Kestrel keeps a single HTTPS-defaults delegate and replaces it on every ConfigureHttpsDefaults
/// call, so the order in which AutoHttps and the application configure HTTPS decides whose settings
/// survive. These pin the two outcomes that must never regress: AutoHttps preserves the application's
/// own selector when it is added after it, and a call that replaces AutoHttps's selector fails at
/// startup with a message that names the cause instead of failing opaquely or, in Development,
/// serving the developer certificate for a managed domain.
/// </summary>
public class KestrelWiringTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task ReplacingTheSelectorWithALaterConfigureHttpsDefaultsFailsFastAndNamesAutoHttps()
    {
        using var storage = new TempStorage();

        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("https://127.0.0.1:0");

        builder.Services.AddAutoHttps(options =>
        {
            options.DomainNames.Add("managed.example.com");
            options.EmailAddress = "operator@example.com";
            options.AcceptTermsOfService = true;
            options.CertificateAuthority = new Uri("http://127.0.0.1:1/dir");
            options.StorageDirectory = storage.Path;
        });

        // Placed after AddAutoHttps, as an ordinary Program.cs would, this replaces AutoHttps's selector.
        builder.WebHost.ConfigureKestrel(kestrel =>
            kestrel.ConfigureHttpsDefaults(https => https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13));

        await using WebApplication app = builder.Build();

        InvalidOperationException error =
            await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync());

        Assert.Contains("AutoHttps", error.Message, StringComparison.Ordinal);
        Assert.Contains("ConfigureHttpsDefaults", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AddedAfterConfigureHttpsDefaultsAutoHttpsServesManagedNamesAndKeepsTheAppSelector()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        using X509Certificate2 legacy = CertificateFactory.CreateSelfSigned(
            ["legacy.example.com"], DateTimeOffset.UtcNow, TimeSpan.FromDays(30));

        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0", "https://127.0.0.1:0");

        // The slim builder does not wire up HTTPS-from-address support the full builder includes, so
        // an https:// URL needs this. It has nothing to do with AutoHttps; a full builder omits it.
        builder.WebHost.UseKestrelHttpsConfiguration();

        // The application configures its own HTTPS defaults first: a selector for a name it owns and a
        // TLS setting. AutoHttps is added afterwards and must keep both while taking over the managed name.
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.ConfigureHttpsDefaults(https =>
        {
            https.HandshakeTimeout = HandshakeTimeout;
            https.ServerCertificateSelector = (_, name) =>
                string.Equals(name, "legacy.example.com", StringComparison.OrdinalIgnoreCase) ? legacy : null;
        }));

        builder.Services.AddAutoHttps(options =>
        {
            options.DomainNames.Add("managed.example.com");
            options.EmailAddress = "operator@example.com";
            options.AcceptTermsOfService = true;
            options.CertificateAuthority = authority.DirectoryUri;
            options.StorageDirectory = storage.Path;
            options.PollInterval = TimeSpan.FromMilliseconds(100);
            options.ValidationTimeout = TimeSpan.FromSeconds(30);
            options.InitialRetryDelay = TimeSpan.FromMilliseconds(200);
            options.MaxRetryDelay = TimeSpan.FromSeconds(2);
            options.ServeFallbackCertificate = false;
        });

        await using WebApplication app = builder.Build();
        app.MapGet("/", () => "ok");
        await app.StartAsync();

        int httpPort = ReadPort(app, "http");
        int httpsPort = ReadPort(app, "https");
        authority.HttpChallengeResolver = _ => new Uri($"http://127.0.0.1:{httpPort}/");

        CertificateSelector selector = app.Services.GetRequiredService<CertificateSelector>();
        await WaitForManagedAsync(selector, "managed.example.com", IssuanceTimeout);

        X509Certificate2 managed = await HandshakeAsync(httpsPort, "managed.example.com");
        Assert.Contains("AutoHttps Test", managed.Issuer, StringComparison.Ordinal);

        // The application's own selector still answers the name AutoHttps does not manage.
        X509Certificate2 served = await HandshakeAsync(httpsPort, "legacy.example.com");
        Assert.Equal(legacy.Thumbprint, served.Thumbprint);
    }

    [Fact]
    public async Task EndpointDeclaredBeforeAddAutoHttpsIsReportedWhenTheHostStarts()
    {
        using var storage = new TempStorage();
        var logs = new LogCapture();

        using X509Certificate2 other = CertificateFactory.CreateSelfSigned(
            ["localhost"], DateTimeOffset.UtcNow, TimeSpan.FromDays(30));

        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(logs);
        builder.WebHost.UseKestrelHttpsConfiguration();

        // The HTTPS endpoint is declared before AddAutoHttps, so UseHttps copies the HTTPS defaults as
        // they are now, before AutoHttps installs its selector. AutoHttps is never consulted for this
        // endpoint, which then serves 'other' for the managed name. The guard reports that once started.
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(0, listen => listen.UseHttps(other)));

        builder.Services.AddAutoHttps(options =>
        {
            options.DomainNames.Add("managed.example.com");
            options.EmailAddress = "operator@example.com";
            options.AcceptTermsOfService = true;
            options.CertificateAuthority = new Uri("http://127.0.0.1:1/dir");
            options.StorageDirectory = storage.Path;
            options.ServeFallbackCertificate = false;
        });

        await using WebApplication app = builder.Build();
        await app.StartAsync();
        await app.StopAsync();

        Assert.True(logs.CountOf(142) > 0, logs.Describe());
    }

    [Fact]
    public async Task EndpointBoundAfterAddAutoHttpsIsNotReported()
    {
        using var storage = new TempStorage();
        var logs = new LogCapture();

        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(logs);
        builder.WebHost.UseKestrelHttpsConfiguration();

        builder.Services.AddAutoHttps(options =>
        {
            options.DomainNames.Add("managed.example.com");
            options.EmailAddress = "operator@example.com";
            options.AcceptTermsOfService = true;
            options.CertificateAuthority = new Uri("http://127.0.0.1:1/dir");
            options.StorageDirectory = storage.Path;
        });

        // The address binds during server start, after AutoHttps has installed its selector, so the
        // composer runs for it and the guard stays quiet.
        builder.WebHost.UseUrls("https://127.0.0.1:0");

        await using WebApplication app = builder.Build();
        await app.StartAsync();
        await app.StopAsync();

        Assert.Equal(0, logs.CountOf(142));
    }

    private static async Task WaitForManagedAsync(CertificateSelector selector, string hostName, TimeSpan timeout)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (selector.Find(hostName) is not null)
            {
                return;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException($"No certificate for '{hostName}' was published within {timeout}.");
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

    private static async Task<X509Certificate2> HandshakeAsync(int httpsPort, string serverName)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, httpsPort);

        X509Certificate2? presented = null;
        using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, certificate, _, _) =>
        {
            if (certificate is not null)
            {
                presented = new X509Certificate2(certificate);
            }

            return true;
        });

        await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = serverName });

        return presented ?? throw new InvalidOperationException("The server presented no certificate.");
    }
}
