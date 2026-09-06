using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;

namespace AutoHttps.Hosting;

/// <summary>
/// Publishes AutoHttps metrics through a <see cref="Meter"/> named
/// <see cref="AutoHttpsDefaults.MeterName"/>. The instruments cost nothing until something listens
/// for them, so they are always on; subscribe with OpenTelemetry or a <see cref="MeterListener"/>.
/// </summary>
internal sealed class AutoHttpsMetrics : IDisposable
{
    private readonly Meter _meter;
    private readonly Counter<long> _renewals;
    private readonly AutoHttpsState _state;
    private readonly TimeProvider _time;

    public AutoHttpsMetrics(IMeterFactory meterFactory, AutoHttpsState state, TimeProvider time)
    {
        _state = state;
        _time = time;
        _meter = meterFactory.Create(AutoHttpsDefaults.MeterName);

        _meter.CreateObservableGauge(
            "autohttps.certificate.expiry",
            ObserveExpiry,
            unit: "s",
            description: "Seconds until the managed certificate expires, negative once it has expired.");

        _renewals = _meter.CreateCounter<long>(
            "autohttps.certificate.renewals",
            unit: "{renewal}",
            description: "Certificate orders this instance completed, tagged by outcome.");
    }

    public void RecordSuccess() =>
        _renewals.Add(1, new KeyValuePair<string, object?>("outcome", "success"));

    public void RecordFailure() =>
        _renewals.Add(1, new KeyValuePair<string, object?>("outcome", "failure"));

    public void Dispose() => _meter.Dispose();

    private IEnumerable<Measurement<double>> ObserveExpiry()
    {
        // No series is reported until a certificate exists, so a dashboard does not draw a
        // misleading zero for the window before the first one is obtained.
        if (_state.Current.Certificate is not { } certificate)
        {
            yield break;
        }

        // The thumbprint names the certificate a replica is actually serving, so a dashboard can tell
        // a replica that is stale relative to its peers, not only that an order succeeded somewhere.
        // It changes at each renewal, which adds one new series per renewal; that churn is bounded.
        double seconds = (certificate.NotAfter - _time.GetUtcNow()).TotalSeconds;
        yield return new Measurement<double>(
            seconds,
            new KeyValuePair<string, object?>("autohttps.certificate.thumbprint", certificate.Thumbprint));
    }
}
