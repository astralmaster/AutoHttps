using System;
using System.Net;
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
/// Adding certificate automation to an application that already serves a certificate of its own is
/// the normal way this library gets adopted. LettuceEncrypt issue 122 reports that merely
/// referencing it broke every request whose server name it did not recognise, because its selector
/// replaced the configured certificate and then returned nothing.
/// </summary>
public class CoexistenceTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task AnExistingCertificateKeepsWorkingForNamesAutoHttpsDoesNotManage()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        using X509Certificate2 existing = CertificateFactory.CreateSelfSigned(
            ["legacy.example.com"], DateTimeOffset.UtcNow, TimeSpan.FromDays(30));

        await using var app = await MixedApplication.StartAsync(authority, existing, storage.Path);

        await app.WaitForCertificateAsync("managed.example.com", IssuanceTimeout);

        X509Certificate2 managed = await app.HandshakeAsync("managed.example.com");
        Assert.Contains("AutoHttps Test", managed.Issuer, StringComparison.Ordinal);

        // The endpoint's own certificate has to survive. Dropping this connection is what issue 122
        // describes, and it would take out every name the application already served.
        X509Certificate2 legacy = await app.HandshakeAsync("legacy.example.com");
        Assert.Equal(existing.Thumbprint, legacy.Thumbprint);
    }

    [Fact]
    public async Task AClientSendingNoServerNameStillReachesTheExistingCertificate()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        using X509Certificate2 existing = CertificateFactory.CreateSelfSigned(
            ["legacy.example.com"], DateTimeOffset.UtcNow, TimeSpan.FromDays(30));

        await using var app = await MixedApplication.StartAsync(authority, existing, storage.Path);
        await app.WaitForCertificateAsync("managed.example.com", IssuanceTimeout);

        // Scanners and anything connecting by IP send no server name at all. That request was
        // answered with the application's own certificate before AutoHttps was added, and taking it
        // over would change behaviour nobody asked to change.
        X509Certificate2 served = await app.HandshakeAsync(string.Empty);
        Assert.Equal(existing.Thumbprint, served.Thumbprint);
    }

    [Fact]
    public async Task WithNothingElseConfiguredAutoHttpsStillAnswersARequestWithNoServerName()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate managed = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // Deferring to the application must not become "serve nothing" when there is no application
        // certificate to defer to.
        TlsHandshakeResult handshake = await app.HandshakeAsync(string.Empty, authority.RootCertificate);
        Assert.Equal(managed.Leaf.Thumbprint, handshake.Leaf.Thumbprint);
    }

    private sealed class MixedApplication : IAsyncDisposable
    {
        private readonly WebApplication _app;

        private MixedApplication(WebApplication app)
        {
            _app = app;
            HttpsPort = new Uri(System.Linq.Enumerable.First(app.Urls, u => u.StartsWith("https", StringComparison.Ordinal))).Port;
        }

        public int HttpsPort { get; }

        public static async Task<MixedApplication> StartAsync(
            TestCertificateAuthority authority,
            X509Certificate2 existingCertificate,
            string storageDirectory)
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();

            builder.Services.AddAutoHttps(options =>
            {
                options.DomainNames.Add("managed.example.com");
                options.EmailAddress = "operator@example.com";
                options.AcceptTermsOfService = true;
                options.CertificateAuthority = authority.DirectoryUri;
                options.StorageDirectory = storageDirectory;
                options.PollInterval = TimeSpan.FromMilliseconds(100);
                options.ServeFallbackCertificate = false;
            });

            builder.WebHost.ConfigureKestrel(kestrel =>
            {
                kestrel.Listen(IPAddress.Loopback, 0);

                // The application already had a certificate here before AutoHttps was added.
                kestrel.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(
                    existingCertificate,
                    https => https.HandshakeTimeout = TimeSpan.FromSeconds(60)));
            });

            WebApplication app = builder.Build();
            app.MapGet("/", () => "ok");
            await app.StartAsync();

            var instance = new MixedApplication(app);
            int httpPort = new Uri(System.Linq.Enumerable.First(app.Urls, u => u.StartsWith("http:", StringComparison.Ordinal))).Port;
            authority.HttpChallengeResolver = _ => new Uri($"http://127.0.0.1:{httpPort}/");

            return instance;
        }

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

            throw new TimeoutException($"No certificate for '{hostName}' within {timeout}.");
        }

        public async Task<X509Certificate2> HandshakeAsync(string serverName)
        {
            using var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, HttpsPort);

            X509Certificate2? presented = null;
            using var stream = new System.Net.Security.SslStream(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                (_, certificate, _, _) =>
                {
                    if (certificate is not null)
                    {
                        presented = new X509Certificate2(certificate);
                    }

                    return true;
                });

            await stream.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
            {
                TargetHost = serverName,
            });

            return presented ?? throw new InvalidOperationException("The server presented no certificate.");
        }

        public ValueTask DisposeAsync() => _app.DisposeAsync();
    }
}
