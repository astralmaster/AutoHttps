using System;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Xunit;

// System.Net.Quic is annotated as a preview API (CA2252) and as supported only on Linux, macOS and
// Windows (CA1416). Every call below is behind a QuicConnection.IsSupported check, which is the
// guard the analyzers cannot see, and none of this ships: it is test code that verifies the library
// against the protocol rather than library code itself.
#pragma warning disable CA2252, CA1416

namespace AutoHttps.IntegrationTests;

/// <summary>
/// Kestrel builds a second, separate set of TLS options for HTTP/3, because QUIC terminates TLS in
/// the transport rather than in the HTTPS middleware. Some HTTPS settings are rejected outright
/// there, which is how enabling HTTP/3 broke certificate selection in LettuceEncrypt (#228, open for
/// two years) and in its fork (Archon #15): both configured TLS through OnAuthenticate, which throws
/// NotSupportedException on the HTTP/3 path. AutoHttps uses a certificate selector and a handshake
/// callback, neither of which Kestrel refuses, and these tests are what keeps that true.
/// </summary>
public class Http3Tests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    private static readonly SslApplicationProtocol Http3 = new("h3");

    [Fact]
    public async Task TheHttpsDefaultsWiringServesTheManagedCertificateOnAnHttp3Endpoint()
    {
        await AssertServesManagedCertificateAsync(KestrelIntegration.HttpsDefaults);
    }

    [Fact]
    public async Task TheListenerWiringServesTheManagedCertificateOnAnHttp3Endpoint()
    {
        await AssertServesManagedCertificateAsync(KestrelIntegration.ListenOptions);
    }

    [Fact]
    public async Task AQuicHandshakeGetsTheManagedCertificate()
    {
        if (!QuicConnection.IsSupported)
        {
            // No MsQuic on this host. The endpoint still binds for HTTP/1.1 and HTTP/2, which the
            // tests above cover; the QUIC half runs wherever MsQuic is present, including Linux CI
            // and the container rig under test/docker.
            return;
        }

        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            Configure(storage),
            protocols: HttpProtocols.Http1AndHttp2AndHttp3);

        ServerCertificate expected = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // A raw QUIC handshake rather than an HTTP/3 request, because the remote endpoint and the
        // server name can be set independently here. An HttpClient speaking HTTP/3 takes both from
        // the URI, and "app.example.com" does not resolve on the machine running this.
        X509Certificate2 served = await QuicHandshakeAsync(app.HttpsPort, "app.example.com");

        using (served)
        {
            Assert.Equal(expected.Leaf.Thumbprint, served.Thumbprint);
        }
    }

    private static async Task AssertServesManagedCertificateAsync(KestrelIntegration integration)
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            Configure(storage),
            integration,
            protocols: HttpProtocols.Http1AndHttp2AndHttp3);

        ServerCertificate expected = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // The endpoint offers all three protocols. Over TCP a client still negotiates HTTP/2 or
        // HTTP/1.1 and still gets the managed certificate, so declaring HTTP/3 costs nothing for
        // clients that cannot speak it.
        TlsHandshakeResult handshake = await app.HandshakeAsync(
            "app.example.com",
            applicationProtocols: [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]);

        Assert.Equal(expected.Leaf.Thumbprint, handshake.Leaf.Thumbprint);
        Assert.Contains(
            handshake.NegotiatedProtocol,
            new[] { SslApplicationProtocol.Http2, SslApplicationProtocol.Http11 });

        // Kestrel reports a refused HTTPS configuration by failing the endpoint, which shows up as
        // an error from its own categories rather than as a bad certificate.
        Assert.DoesNotContain(
            app.Log.Entries,
            entry => entry.Contains("NotSupportedException", StringComparison.Ordinal));
    }

    private static async Task<X509Certificate2> QuicHandshakeAsync(int port, string serverName)
    {
        X509Certificate2? captured = null;

        var options = new QuicClientConnectionOptions
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, port),
            DefaultStreamErrorCode = 0,
            DefaultCloseErrorCode = 0,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                TargetHost = serverName,
                ApplicationProtocols = [Http3],
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    if (certificate is not null)
                    {
                        captured = new X509Certificate2(certificate);
                    }

                    // The test authority is not a trusted root here. What this test is about is which
                    // certificate the QUIC path selects, not whether the client would trust it.
                    return true;
                },
            },
        };

        await using QuicConnection connection = await QuicConnection.ConnectAsync(options);
        await connection.CloseAsync(0);

        return captured ?? throw new InvalidOperationException("The server presented no certificate over QUIC.");
    }

    private static Action<AutoHttpsOptions> Configure(TempStorage storage) => options =>
    {
        options.DomainNames.Add("app.example.com");
        options.StorageDirectory = storage.Path;
    };
}
