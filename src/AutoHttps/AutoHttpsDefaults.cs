namespace AutoHttps;

/// <summary>
/// Constants shared by AutoHttps and applications that extend it.
/// </summary>
public static class AutoHttpsDefaults
{
    /// <summary>
    /// The name of the <see cref="System.Net.Http.HttpClient"/> used to talk to the certificate
    /// authority. Configure it to route ACME traffic through a proxy or to add handlers.
    /// </summary>
    public const string HttpClientName = "AutoHttps.Acme";

    /// <summary>
    /// The name of the <see cref="System.Diagnostics.Metrics.Meter"/> AutoHttps publishes its
    /// instruments through. Subscribe to it with OpenTelemetry or a
    /// <see cref="System.Diagnostics.Metrics.MeterListener"/>.
    /// </summary>
    public const string MeterName = "AutoHttps";
}
