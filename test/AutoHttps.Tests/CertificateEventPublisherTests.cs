using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AutoHttps.Tests;

public class CertificateEventPublisherTests
{
    [Fact]
    public async Task EveryListenerHearsAChange()
    {
        var first = new RecordingListener();
        var second = new RecordingListener();
        var publisher = Publisher(first, second);

        await publisher.NotifyChangedAsync(Changed(CertificateChangeReason.Issued), CancellationToken.None);

        Assert.Equal(CertificateChangeReason.Issued, first.LastChange?.Reason);
        Assert.Equal(CertificateChangeReason.Issued, second.LastChange?.Reason);
    }

    [Fact]
    public async Task AListenerThatThrowsDoesNotStopTheOthers()
    {
        var throwing = new ThrowingListener();
        var recording = new RecordingListener();

        // Order matters: the throwing listener runs first, so if its exception escaped, the second
        // would never be called and the renewal loop that invoked this would fault.
        var publisher = Publisher(throwing, recording);

        await publisher.NotifyChangedAsync(Changed(CertificateChangeReason.Renewed), CancellationToken.None);
        await publisher.NotifyFailedAsync(Failed(), CancellationToken.None);

        Assert.Equal(CertificateChangeReason.Renewed, recording.LastChange?.Reason);
        Assert.NotNull(recording.LastFailure);
    }

    [Fact]
    public void TwoInstancesOfTheSameListenerClassAreBothRegistered()
    {
        // One class configured twice, for example a webhook per endpoint. Telling them apart by type
        // dropped the second without a word, so only one endpoint ever heard of a renewal.
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        IAutoHttpsBuilder builder = services.AddAutoHttps(options => options.DomainNames.Add("app.example.com"));
        var first = new RecordingListener();
        var second = new RecordingListener();

        builder.AddCertificateListener(first).AddCertificateListener(second).AddCertificateListener(first);

        object?[] registered = [.. services
            .Where(descriptor => descriptor.ServiceType == typeof(IAutoHttpsCertificateListener))
            .Select(descriptor => descriptor.ImplementationInstance)];

        Assert.Equal(2, registered.Length);
        Assert.Contains(first, registered);
        Assert.Contains(second, registered);
    }

    private static CertificateEventPublisher Publisher(params IAutoHttpsCertificateListener[] listeners) =>
        new(listeners, NullLogger<CertificateEventPublisher>.Instance);

    private static CertificateChangedContext Changed(CertificateChangeReason reason) => new(
        ["app.example.com"],
        ["app.example.com"],
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow.AddDays(30),
        "THUMBPRINT",
        reason);

    private static CertificateFailedContext Failed() =>
        new(["app.example.com"], "validation failed", new InvalidOperationException("boom"));

    private sealed class RecordingListener : IAutoHttpsCertificateListener
    {
        public CertificateChangedContext? LastChange { get; private set; }

        public CertificateFailedContext? LastFailure { get; private set; }

        public Task OnCertificateChangedAsync(CertificateChangedContext context, CancellationToken cancellationToken)
        {
            LastChange = context;
            return Task.CompletedTask;
        }

        public Task OnCertificateFailedAsync(CertificateFailedContext context, CancellationToken cancellationToken)
        {
            LastFailure = context;
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingListener : IAutoHttpsCertificateListener
    {
        public Task OnCertificateChangedAsync(CertificateChangedContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("this listener is broken");

        public Task OnCertificateFailedAsync(CertificateFailedContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("this listener is broken");
    }
}
