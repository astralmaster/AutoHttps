using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.IntegrationTests.TestCa;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace AutoHttps.IntegrationTests;

public class LifecycleTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task AListenerHearsTheIssuedCertificate()
    {
        var listener = new RecordingListener();
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureServices: services => services.AddSingleton<IAutoHttpsCertificateListener>(listener));

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        CertificateChangedContext changed = await listener.Changed.WaitAsync(IssuanceTimeout);

        Assert.Equal(CertificateChangeReason.Issued, changed.Reason);
        Assert.Contains("app.example.com", changed.SubjectNames);
        Assert.Equal(["app.example.com"], changed.Domains.ToArray());
        Assert.True(changed.NotAfter > changed.NotBefore);
    }

    [Fact]
    public async Task AListenerHearsAFailedOrder()
    {
        var listener = new RecordingListener();
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.FailValidation = true;

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureServices: services => services.AddSingleton<IAutoHttpsCertificateListener>(listener));

        CertificateFailedContext failed = await listener.Failed.WaitAsync(IssuanceTimeout);

        Assert.NotNull(failed.Exception);
        Assert.False(string.IsNullOrWhiteSpace(failed.Reason));
    }

    [Fact]
    public async Task TheInspectorReflectsTheIssuedCertificate()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        Certificates.ServerCertificate issued = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        AutoHttpsCertificateStatus status = app.Services
            .GetRequiredService<IAutoHttpsCertificateInspector>()
            .GetStatus();

        Assert.True(status.HasCertificate);
        Assert.Equal(issued.Leaf.Thumbprint, status.Thumbprint);
        Assert.Equal(issued.NotAfter, status.NotAfter);
        Assert.Contains("app.example.com", status.SubjectNames);
    }

    [Fact]
    public async Task TheHealthCheckIsHealthyOnceACertificateIsServed()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureServices: services => services.AddHealthChecks().AddAutoHttps());

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        HealthReport report = await app.Services
            .GetRequiredService<HealthCheckService>()
            .CheckHealthAsync();

        Assert.Equal(HealthStatus.Healthy, report.Status);
        Assert.Equal(HealthStatus.Healthy, report.Entries["autohttps"].Status);
    }

    [Fact]
    public async Task TheHealthCheckReportsTheMissingStatusWhileNoCertificateExists()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.FailValidation = true;

        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            configureServices: services => services.AddHealthChecks().AddAutoHttps());

        HealthReport report = await app.Services
            .GetRequiredService<HealthCheckService>()
            .CheckHealthAsync();

        // No certificate has been obtained, so the default missing status applies rather than a hard
        // failure: a self-signed fallback is still being served.
        Assert.Equal(HealthStatus.Degraded, report.Entries["autohttps"].Status);
        Assert.False(app.Services.GetRequiredService<IAutoHttpsCertificateInspector>().GetStatus().HasCertificate);
    }

    private sealed class RecordingListener : IAutoHttpsCertificateListener
    {
        private readonly TaskCompletionSource<CertificateChangedContext> _changed =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly TaskCompletionSource<CertificateFailedContext> _failed =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<CertificateChangedContext> Changed => _changed.Task;

        public Task<CertificateFailedContext> Failed => _failed.Task;

        public Task OnCertificateChangedAsync(CertificateChangedContext context, CancellationToken cancellationToken)
        {
            _changed.TrySetResult(context);
            return Task.CompletedTask;
        }

        public Task OnCertificateFailedAsync(CertificateFailedContext context, CancellationToken cancellationToken)
        {
            _failed.TrySetResult(context);
            return Task.CompletedTask;
        }
    }
}
