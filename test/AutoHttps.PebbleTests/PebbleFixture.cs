using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace AutoHttps.PebbleTests;

/// <summary>
/// Talks to a running Pebble instance and the challenge test server that resolves DNS for it.
/// See test/pebble/docker-compose.yml.
/// </summary>
public sealed class PebbleFixture : IAsyncLifetime
{
    /// <summary>The port Pebble connects to when validating an <c>http-01</c> challenge.</summary>
    public const int HttpChallengePort = 5002;

    // Pebble rejects any request without a User-Agent, which is a rule real authorities apply too.
    private readonly HttpClient _management = CreateClient(trustAnything: false);
    private readonly HttpClient _insecure = CreateClient(trustAnything: true);

    private static HttpClient CreateClient(bool trustAnything)
    {
        var handler = new HttpClientHandler();
        if (trustAnything)
        {
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("AutoHttps.PebbleTests/1.0");

        return client;
    }

    public Uri DirectoryUri { get; } = new("https://localhost:14000/dir");

    public Uri ChallengeTestServer { get; } = new("http://localhost:8055/");

    /// <summary>The address Pebble reaches the test host on, published to DNS for every test domain.</summary>
    public string HostAddress { get; } = Environment.GetEnvironmentVariable("AUTOHTTPS_HOST_ADDRESS") ?? "192.168.65.254";

    public X509Certificate2 PebbleRoot { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await EnsurePebbleIsRunningAsync();
        await PublishHostAddressAsync();

        PebbleRoot = await FetchRootAsync();
    }

    public Task DisposeAsync()
    {
        PebbleRoot?.Dispose();
        _management.Dispose();
        _insecure.Dispose();

        return Task.CompletedTask;
    }

    /// <summary>Points every unqualified lookup at the machine running the tests.</summary>
    private async Task PublishHostAddressAsync()
    {
        await PostAsync("set-default-ipv4", new { ip = HostAddress });
        await PostAsync("set-default-ipv6", new { ip = string.Empty });
    }

    public Task AddTxtRecordAsync(string host, string value) =>
        PostAsync("set-txt", new { host = Qualify(host), value });

    public Task RemoveTxtRecordAsync(string host) =>
        PostAsync("clear-txt", new { host = Qualify(host) });

    /// <summary>
    /// Trusts Pebble's own TLS certificate. Pebble serves its ACME API over HTTPS with a private
    /// root, so the client that talks to it has to be told about that root.
    /// </summary>
    public HttpClientHandler CreateAcmeHandler()
    {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
            certificate is not null && IsSignedByPebble(certificate);

        return handler;
    }

    private static bool IsSignedByPebble(X509Certificate2 certificate) =>
        certificate.Issuer.Contains("Pebble", StringComparison.OrdinalIgnoreCase) ||
        certificate.Issuer.Contains("minica", StringComparison.OrdinalIgnoreCase);

    private async Task EnsurePebbleIsRunningAsync()
    {
        try
        {
            using HttpResponseMessage response = await _insecure.GetAsync(DirectoryUri);
            response.EnsureSuccessStatusCode();

            string body = await response.Content.ReadAsStringAsync();
            using JsonDocument directory = JsonDocument.Parse(body);

            if (!directory.RootElement.TryGetProperty("newOrder", out _))
            {
                throw new InvalidOperationException("The endpoint at " + DirectoryUri + " is not an ACME directory.");
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new InvalidOperationException(
                $"Pebble is not reachable at {DirectoryUri}. Start it with:{Environment.NewLine}" +
                "    docker compose -f test/pebble/docker-compose.yml up -d",
                ex);
        }
    }

    private async Task<X509Certificate2> FetchRootAsync()
    {
        string pem = await _insecure.GetStringAsync(new Uri("https://localhost:15000/roots/0"));
        return X509Certificate2.CreateFromPem(pem);
    }

    private async Task PostAsync(string path, object payload)
    {
        using HttpResponseMessage response = await _management.PostAsJsonAsync(new Uri(ChallengeTestServer, path), payload);
        response.EnsureSuccessStatusCode();
    }

    private static string Qualify(string host) => host.EndsWith('.') ? host : host + ".";
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PebbleCollection : ICollectionFixture<PebbleFixture>
{
    public const string Name = "pebble";
}
