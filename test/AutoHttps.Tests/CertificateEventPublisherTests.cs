using System;
using System.Collections.Generic;
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
