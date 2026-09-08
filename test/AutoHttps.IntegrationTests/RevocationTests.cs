using System;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AutoHttps.IntegrationTests;

public sealed class RevocationTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task RevokesTheServedCertificateWithTheGivenReason()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority, options => options.DomainNames.Add("revoke.example"));

        ServerCertificate certificate = await app.WaitForCertificateAsync("revoke.example", Timeout);
        string thumbprint = certificate.Leaf.Thumbprint;

        var manager = app.Services.GetRequiredService<IAutoHttpsCertificateManager>();
        bool revoked = await manager.RevokeCurrentAsync(RevocationReason.KeyCompromise, CancellationToken.None);

        Assert.True(revoked);
        Assert.True(authority.Revocations.TryGetValue(thumbprint, out int reason));
        Assert.Equal((int)RevocationReason.KeyCompromise, reason);
        Assert.True(app.Log.CountOf(138) > 0);
    }

    [Fact]
    public async Task RevokesASuppliedCertificate()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(
            authority, options => options.DomainNames.Add("revoke-supplied.example"));

        ServerCertificate certificate = await app.WaitForCertificateAsync("revoke-supplied.example", Timeout);

        var manager = app.Services.GetRequiredService<IAutoHttpsCertificateManager>();
        await manager.RevokeAsync(certificate.Leaf, RevocationReason.Superseded, CancellationToken.None);

        Assert.Equal((int)RevocationReason.Superseded, authority.Revocations[certificate.Leaf.Thumbprint]);
    }

    [Fact]
    public async Task RevokeCurrentReturnsFalseWhenNothingIsServed()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // Nothing validates, so no certificate is ever served and there is nothing to revoke.
        authority.Behavior.FailValidation = true;

        await using TestApplication app = await TestApplication.StartAsync(
            authority, options => options.DomainNames.Add("never-issued.example"));

        var manager = app.Services.GetRequiredService<IAutoHttpsCertificateManager>();

        Assert.False(await manager.RevokeCurrentAsync(RevocationReason.Unspecified, CancellationToken.None));
    }
}
