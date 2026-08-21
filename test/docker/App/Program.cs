using AutoHttps;

string domain = Environment.GetEnvironmentVariable("DOMAIN") ?? throw new InvalidOperationException("DOMAIN is required.");
string directory = Environment.GetEnvironmentVariable("ACME_DIRECTORY") ?? throw new InvalidOperationException("ACME_DIRECTORY is required.");
bool useListenerWiring = (Environment.GetEnvironmentVariable("MODE") ?? "listener") == "listener";

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

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(5002);

    if (useListenerWiring)
    {
        kestrel.ListenAnyIP(5443, listen => listen.UseAutoHttps(kestrel.ApplicationServices));
    }
    else
    {
        kestrel.ListenAnyIP(5443, listen => listen.UseHttps());
    }
});

WebApplication app = builder.Build();
app.MapGet("/", () => $"ok from {Environment.MachineName}");
app.Run();
