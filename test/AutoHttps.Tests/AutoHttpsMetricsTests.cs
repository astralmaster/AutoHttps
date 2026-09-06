using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Certificates;
using AutoHttps.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public class AutoHttpsMetricsTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void TheExpiryGaugeReportsNothingUntilACertificateExists()
    {
        using var host = new MetricsHost(Now);

        Assert.Empty(host.ReadGauge());
    }

    [Fact]
    public void TheExpiryGaugeReportsSecondsUntilTheCertificateExpires()
    {
        using var host = new MetricsHost(Now);
        using ServerCertificate certificate = SelfSigned(host.Time, TimeSpan.FromDays(5));
        host.State.CertificatePublished(certificate);

        double seconds = Assert.Single(host.ReadGauge());

        Assert.InRange(
            seconds,
            TimeSpan.FromDays(5).TotalSeconds - 60,
            TimeSpan.FromDays(5).TotalSeconds + 60);
    }

    [Fact]
    public void TheExpiryGaugeGoesNegativeOnceTheCertificateHasExpired()
    {
        using var host = new MetricsHost(Now);
        using ServerCertificate certificate = SelfSigned(host.Time, TimeSpan.FromDays(1));
        host.State.CertificatePublished(certificate);

        host.Time.Advance(TimeSpan.FromDays(2));

        Assert.True(Assert.Single(host.ReadGauge()) < 0);
    }

    [Fact]
    public void TheExpiryGaugeCarriesTheServedThumbprint()
    {
        using var host = new MetricsHost(Now);
        using ServerCertificate certificate = SelfSigned(host.Time, TimeSpan.FromDays(5));
        host.State.CertificatePublished(certificate);

        host.ReadGauge();

        Assert.Equal(certificate.Leaf.Thumbprint, host.LastGaugeThumbprint);
    }

    [Fact]
    public void RenewalsAreCountedByOutcome()
    {
        using var host = new MetricsHost(Now);

        host.Metrics.RecordSuccess();
        host.Metrics.RecordSuccess();
        host.Metrics.RecordFailure();

        Assert.Equal(2, host.CountFor("success"));
        Assert.Equal(1, host.CountFor("failure"));
    }

    private static ServerCertificate SelfSigned(FakeTimeProvider time, TimeSpan lifetime) => new(
        CertificateFactory.CreateSelfSigned(["app.example.com"], time.GetUtcNow(), lifetime),
        new X509Certificate2Collection());

    private sealed class MetricsHost : IDisposable
    {
        private readonly ServiceProvider _services;
        private readonly MeterListener _listener = new();
        private readonly List<double> _gauge = [];
        private readonly Dictionary<string, long> _counts = new(StringComparer.Ordinal);

        public MetricsHost(DateTimeOffset now)
        {
            Time = new FakeTimeProvider(now);
            State = new AutoHttpsState();
            _services = new ServiceCollection().AddMetrics().BuildServiceProvider();
            Metrics = new AutoHttpsMetrics(_services.GetRequiredService<IMeterFactory>(), State, Time);

            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == AutoHttpsDefaults.MeterName)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<double>((_, measurement, tags, _) =>
            {
                _gauge.Add(measurement);
                foreach (KeyValuePair<string, object?> tag in tags)
                {
                    if (tag.Key == "autohttps.certificate.thumbprint" && tag.Value is string thumbprint)
                    {
                        LastGaugeThumbprint = thumbprint;
                    }
                }
            });
            _listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
            {
                foreach (KeyValuePair<string, object?> tag in tags)
                {
                    if (tag.Key == "outcome" && tag.Value is string outcome)
                    {
                        _counts[outcome] = _counts.GetValueOrDefault(outcome) + measurement;
                    }
                }
            });
            _listener.Start();
        }

        public FakeTimeProvider Time { get; }

        public AutoHttpsState State { get; }

        public AutoHttpsMetrics Metrics { get; }

        public string? LastGaugeThumbprint { get; private set; }

        public IReadOnlyList<double> ReadGauge()
        {
            _gauge.Clear();
            _listener.RecordObservableInstruments();
            return _gauge;
        }

        public long CountFor(string outcome) => _counts.GetValueOrDefault(outcome);

        public void Dispose()
        {
            _listener.Dispose();
            Metrics.Dispose();
            _services.Dispose();
        }
    }
}
