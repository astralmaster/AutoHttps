using System;
using System.Threading.Tasks;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AutoHttps.IntegrationTests;

public sealed class StartupCertificatePolicyTests
{
    [Fact]
    public async Task StopsTheApplicationWhenNoCertificateArrivesAndItIsRequired()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // Nothing will ever validate, so no certificate is issued and the policy has to act.
        authority.Behavior.FailValidation = true;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("startup-required.example");
            options.RequireCertificateOnStartup = true;
            options.StartupCertificateTimeout = TimeSpan.FromSeconds(2);
        });

        var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();

        Assert.True(
            await WaitForStoppingAsync(lifetime, TimeSpan.FromSeconds(15)),
            "The application was not stopped after the startup certificate timeout." + Environment.NewLine + app.Log.Describe());
        Assert.True(app.Log.CountOf(137) > 0);
    }

    [Fact]
    public async Task KeepsRunningWhenTheCertificateArrivesInTime()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("startup-ok.example");
            options.RequireCertificateOnStartup = true;
            options.StartupCertificateTimeout = TimeSpan.FromSeconds(10);
        });

        await app.WaitForCertificateAsync("startup-ok.example", TimeSpan.FromSeconds(30));

        var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
        await Task.Delay(TimeSpan.FromSeconds(3));

        Assert.False(lifetime.ApplicationStopping.IsCancellationRequested);
        Assert.Equal(0, app.Log.CountOf(137));
    }

    private static async Task<bool> WaitForStoppingAsync(IHostApplicationLifetime lifetime, TimeSpan timeout)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (lifetime.ApplicationStopping.IsCancellationRequested)
            {
                return true;
            }

            await Task.Delay(100);
        }

        return false;
    }
}
