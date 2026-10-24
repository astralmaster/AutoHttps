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
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // Nothing will ever validate, so no certificate is issued and the policy has to act.
        authority.Behavior.FailValidation = true;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("startup-required.example");
            options.StorageDirectory = storage.Path;
            options.RequireCertificateOnStartup = true;
            options.StartupCertificateTimeout = TimeSpan.FromSeconds(2);
        });

        var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();

        try
        {
            Assert.True(
                await WaitForStoppingAsync(lifetime, TimeSpan.FromSeconds(15)),
                "The application was not stopped after the startup certificate timeout." + Environment.NewLine + app.Log.Describe());
            Assert.True(app.Log.CountOf(137) > 0);

            // A process that stops with exit code 0 is not restarted by systemd's Restart=on-failure or
            // Docker's on-failure policy, which would leave it down rather than retrying.
            Assert.NotEqual(0, Environment.ExitCode);
        }
        finally
        {
            // The exit code belongs to the whole test process.
            Environment.ExitCode = 0;
        }
    }

    [Fact]
    public async Task KeepsRunningWhenTheCertificateArrivesInTime()
    {
        // The certificate arrives well inside the timeout, and the application has to still be running
        // once the timeout has passed. Checking before then would also pass for a watcher that stops the
        // application at the timeout regardless of the certificate.
        TimeSpan timeout = TimeSpan.FromSeconds(6);

        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        DateTimeOffset started = DateTimeOffset.UtcNow;
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("startup-ok.example");
            options.StorageDirectory = storage.Path;
            options.RequireCertificateOnStartup = true;
            options.StartupCertificateTimeout = timeout;
        });

        await app.WaitForCertificateAsync("startup-ok.example", timeout);

        TimeSpan pastTheTimeout = started + timeout + TimeSpan.FromSeconds(2) - DateTimeOffset.UtcNow;
        if (pastTheTimeout > TimeSpan.Zero)
        {
            await Task.Delay(pastTheTimeout);
        }

        var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
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
