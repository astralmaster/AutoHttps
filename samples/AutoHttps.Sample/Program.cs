using AutoHttps;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add(builder.Configuration["Domain"] ?? "example.com");
    options.EmailAddress = builder.Configuration["Email"] ?? "admin@example.com";
    options.AcceptTermsOfService = true;

    // Point at the staging environment until the deployment is known to work. Production has
    // rate limits that are easy to exhaust while a setup is still being debugged.
    options.CertificateAuthority = builder.Configuration.GetValue("UseProduction", false)
        ? CertificateAuthorities.LetsEncrypt
        : CertificateAuthorities.LetsEncryptStaging;

    options.StorageDirectory = builder.Configuration["StorageDirectory"];
});

builder.WebHost.ConfigureKestrel(kestrel =>
{
    // Port 80 has to stay reachable: it is where the certificate authority looks for the
    // http-01 challenge response, both for the first certificate and for every renewal.
    kestrel.ListenAnyIP(80);
    kestrel.ListenAnyIP(443, listen => listen.UseAutoHttps(kestrel.ApplicationServices));
});

WebApplication app = builder.Build();

app.MapGet("/", (HttpContext context) =>
    $"Served over {context.Request.Protocol} to {context.Request.Host}. Secure: {context.Request.IsHttps}.");

app.Run();
