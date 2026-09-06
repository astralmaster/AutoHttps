using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AutoHttps.IntegrationTests;

public class DevelopmentCertificateIntegrationTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task ServesTheSuppliedCertificateInDevelopmentAndNeverContactsTheAuthority()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        X509Certificate2 devCertificate = CertificateFactory.CreateSelfSigned(
            ["app.example.com"], DateTimeOffset.UtcNow, TimeSpan.FromDays(1));
        string thumbprint = devCertificate.Thumbprint;

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            environment: "Development",
            configureBuilder: builder => builder.UseDevelopmentCertificate(devCertificate));

        ServerCertificate served = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(thumbprint, served.Leaf.Thumbprint);
        // The whole point: no order was ever placed, because ACME is off in Development.
        Assert.Equal(0, authority.OrderCount);

        AutoHttpsCertificateStatus status = app.Services
            .GetRequiredService<IAutoHttpsCertificateInspector>()
            .GetStatus();
        Assert.True(status.HasCertificate);
        Assert.Equal(thumbprint, status.Thumbprint);
    }

    [Fact]
    public async Task IgnoresTheDevelopmentCertificateOutsideDevelopment()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        X509Certificate2 devCertificate = CertificateFactory.CreateSelfSigned(
            ["app.example.com"], DateTimeOffset.UtcNow, TimeSpan.FromDays(1));
        string devThumbprint = devCertificate.Thumbprint;

        // Same call, but the environment is Production, so it must be ignored and a real order placed.
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureBuilder: builder => builder.UseDevelopmentCertificate(devCertificate));

        ServerCertificate served = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.NotEqual(devThumbprint, served.Leaf.Thumbprint);
        Assert.Contains("AutoHttps Test Intermediate", served.Leaf.Issuer, StringComparison.Ordinal);
        Assert.Equal(1, authority.OrderCount);

        devCertificate.Dispose();
    }
}
