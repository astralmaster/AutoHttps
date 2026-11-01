using System;
using System.Linq;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// Runs on its own, after the parallel tests. It keeps Kestrel's 10 second handshake timeout, which a
/// handshake can exceed on a loaded machine while dozens of other applications start alongside it.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class DefaultHandshakeTimeoutCollection
{
    public const string Name = "Default handshake timeout";
}

[Collection(DefaultHandshakeTimeoutCollection.Name)]
public sealed class DefaultHandshakeTimeoutTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task TheEndpointServesTheCertificateWithNoHandshakeOptionsOfItsOwn()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The two argument overload is what the readme tells people to write, so it has to be the
        // one that is proven to serve a certificate, not just the one the other tests tune.
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            KestrelIntegration.ListenOptions,
            tuneHandshakeTimeout: false);

        ServerCertificate issued = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        TlsHandshakeResult handshake = await app.HandshakeAsync("app.example.com", authority.RootCertificate);

        Assert.Equal(issued.Leaf.Thumbprint, handshake.Leaf.Thumbprint);
        Assert.True(
            handshake.ChainIsTrusted,
            "Chain status: " + string.Join(", ", handshake.ChainStatus.Select(s => s.StatusInformation.Trim())));
    }
}
