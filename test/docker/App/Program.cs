using System.Net;
using System.Security.Cryptography.X509Certificates;
using AutoHttps;
using Microsoft.AspNetCore.Server.Kestrel.Core;

string domain = Environment.GetEnvironmentVariable("DOMAIN") ?? throw new InvalidOperationException("DOMAIN is required.");
string directory = Environment.GetEnvironmentVariable("ACME_DIRECTORY") ?? throw new InvalidOperationException("ACME_DIRECTORY is required.");
bool useListenerWiring = (Environment.GetEnvironmentVariable("MODE") ?? "listener") == "listener";
bool offerHttp3 = (Environment.GetEnvironmentVariable("PROTOCOLS") ?? string.Empty).Contains("h3", StringComparison.Ordinal);
bool http3SelfTest = (Environment.GetEnvironmentVariable("SELFTEST") ?? string.Empty).Contains("h3", StringComparison.Ordinal);

WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
builder.Logging.SetMinimumLevel(LogLevel.Information);
builder.Logging.AddFilter("AutoHttps", LogLevel.Debug);

builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add(domain);
    options.EmailAddress = "ops@example.com";
    options.AcceptTermsOfService = true;
    options.CertificateAuthority = new Uri(directory);
    options.StorageDirectory = "/certs";
    options.PollInterval = TimeSpan.FromMilliseconds(250);
    options.InitialRetryDelay = TimeSpan.FromSeconds(2);
    options.MaxRetryDelay = TimeSpan.FromSeconds(10);
    options.ConfigureKestrel = !useListenerWiring;

    // Knobs used to compress months of renewals into minutes when soak testing.
    if (Environment.GetEnvironmentVariable("PROFILE") is { Length: > 0 } profile)
    {
        options.Profile = profile;
    }

    if (Environment.GetEnvironmentVariable("RENEWAL_THRESHOLD") is { Length: > 0 } threshold)
    {
        options.RenewalThreshold = double.Parse(threshold, System.Globalization.CultureInfo.InvariantCulture);
        options.UseRenewalInformation = false;
    }

    if (Environment.GetEnvironmentVariable("RENEWAL_CHECK_SECONDS") is { Length: > 0 } seconds)
    {
        options.RenewalCheckInterval = TimeSpan.FromSeconds(double.Parse(seconds, System.Globalization.CultureInfo.InvariantCulture));
    }
});

if (offerHttp3)
{
    // CreateSlimBuilder leaves out both of these, and HTTP/3 needs both. Without UseQuic there is no
    // multiplexed transport, so the endpoint binds TCP only and says nothing about it. Without
    // UseKestrelHttpsConfiguration the bind fails outright, because the HTTP/3 path asks that
    // service for the endpoint's TLS settings. CreateBuilder includes both already.
    builder.WebHost.UseQuic();
    builder.WebHost.UseKestrelHttpsConfiguration();
}

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(5002);

    void ConfigureHttps(ListenOptions listen)
    {
        if (offerHttp3)
        {
            // QUIC terminates TLS in the transport rather than in the HTTPS middleware, so this is a
            // second path through the certificate wiring and the reason the rig can ask for it.
            listen.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
        }

        if (useListenerWiring)
        {
            listen.UseAutoHttps(kestrel.ApplicationServices);
        }
        else
        {
            listen.UseHttps();
        }
    }

    kestrel.ListenAnyIP(5443, ConfigureHttps);
});

WebApplication app = builder.Build();
app.MapGet("/", () => $"ok from {Environment.MachineName}");

if (http3SelfTest)
{
    _ = SelfTestHttp3Async(app, domain);
}

app.Run();

// Makes a real HTTP/3 request against this process's own endpoint once a certificate has arrived.
// The container trusts the test authority's root and reaches the certificate's own name through a
// hosts entry, so nothing here relaxes validation: a pass means QUIC negotiated, the managed
// certificate was selected from the SNI, and the chain verified.
static async Task SelfTestHttp3Async(WebApplication app, string domain)
{
    ILogger logger = app.Logger;
    var inspector = app.Services.GetRequiredService<IAutoHttpsCertificateInspector>();

    for (int attempt = 0; attempt < 240 && !inspector.GetStatus().HasCertificate; attempt++)
    {
        await Task.Delay(500);
    }

    if (!inspector.GetStatus().HasCertificate)
    {
        logger.LogError("SELFTEST h3 FAILED no certificate was obtained");
        return;
    }

    if (!System.Net.Quic.QuicConnection.IsSupported)
    {
        logger.LogError("SELFTEST h3 FAILED MsQuic is unavailable in this image");
        return;
    }

    // Pebble signs issued certificates with a root it generates at startup, which is not the minica
    // root the image trusts for Pebble's own management interface. Fetching it is what lets the
    // handshake below be validated for real rather than waved through.
    X509Certificate2? issuingRoot = null;
    X509Certificate2? issuingIntermediate = null;
    try
    {
        using var pemClient = new HttpClient();

        if (Environment.GetEnvironmentVariable("TRUST_ROOTS_URL") is { Length: > 0 } rootsUrl)
        {
            issuingRoot = X509Certificate2.CreateFromPem(await pemClient.GetStringAsync(rootsUrl));
        }

        // Only used to tell "the server did not send its intermediate" apart from "the chain is
        // wrong". Kestrel drops a configured chain whenever a certificate selector is in use, which
        // is the HTTPS-defaults wiring, so that endpoint presents the leaf alone over QUIC as well.
        if (Environment.GetEnvironmentVariable("TRUST_INTERMEDIATES_URL") is { Length: > 0 } intermediatesUrl)
        {
            issuingIntermediate = X509Certificate2.CreateFromPem(await pemClient.GetStringAsync(intermediatesUrl));
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "SELFTEST h3 FAILED could not fetch the authority's own certificates");
        return;
    }

    int presentedCount = 0;

    using var handler = new SocketsHttpHandler
    {
        SslOptions = new System.Net.Security.SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
            {
                presentedCount = chain?.ChainElements.Count ?? 0;
                return errors == System.Net.Security.SslPolicyErrors.None
                    || ChainsToIssuingRoot(certificate, chain, issuingRoot, issuingIntermediate);
            },
        },
    };

    using var client = new HttpClient(handler)
    {
        DefaultRequestVersion = HttpVersion.Version30,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        Timeout = TimeSpan.FromSeconds(30),
    };

    try
    {
        using HttpResponseMessage response = await client.GetAsync($"https://{domain}:5443/");
        string body = (await response.Content.ReadAsStringAsync()).Trim();

        if (response.Version == HttpVersion.Version30 && response.IsSuccessStatusCode)
        {
            logger.LogInformation(
                "SELFTEST h3 OK HTTP/{Version} {Status} chain={Chain} {Body}",
                response.Version,
                (int)response.StatusCode,
                presentedCount,
                body);
        }
        else
        {
            logger.LogError(
                "SELFTEST h3 FAILED HTTP/{Version} {Status}", response.Version, (int)response.StatusCode);
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "SELFTEST h3 FAILED");
    }
}

// Builds the presented chain against the authority's own issuing root rather than the operating
// system's trust store. Everything the server sent goes into the extra store, so a chain that is
// only valid because the client already held the intermediate still fails here.
static bool ChainsToIssuingRoot(
    System.Security.Cryptography.X509Certificates.X509Certificate? certificate,
    X509Chain? presented,
    X509Certificate2? issuingRoot,
    X509Certificate2? issuingIntermediate)
{
    if (certificate is null || issuingRoot is null)
    {
        return false;
    }

    using var chain = new X509Chain();
    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    chain.ChainPolicy.CustomTrustStore.Add(issuingRoot);
    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

    if (presented is not null)
    {
        foreach (X509ChainElement element in presented.ChainElements)
        {
            chain.ChainPolicy.ExtraStore.Add(element.Certificate);
        }
    }

    if (issuingIntermediate is not null)
    {
        chain.ChainPolicy.ExtraStore.Add(issuingIntermediate);
    }

    using var leaf = new X509Certificate2(certificate);
    return chain.Build(leaf);
}
