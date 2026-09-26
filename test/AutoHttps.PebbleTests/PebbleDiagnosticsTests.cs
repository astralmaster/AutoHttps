using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AutoHttps.PebbleTests;

/// <summary>
/// The diagnostics read a real ACME directory here rather than a stub, which is what proves the parsing,
/// the clock comparison and the profile and account-binding checks against a server nobody here wrote.
/// </summary>
[Collection(PebbleCollection.Name)]
public class PebbleDiagnosticsTests
{
    private readonly PebbleFixture _pebble;

    public PebbleDiagnosticsTests(PebbleFixture pebble) => _pebble = pebble;

    [Fact]
    public async Task TheAuthorityAndClockChecksReadARealDirectory()
    {
        using var storage = new TempStorage();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(NewDomain());
            options.StorageDirectory = storage.Path;
        });

        AutoHttpsDiagnosticsReport report = await app.Services
            .GetRequiredService<IAutoHttpsDiagnostics>()
            .RunAsync();

        AutoHttpsCheck authority = Find(report, "authority");
        Assert.Equal(AutoHttpsCheckOutcome.Passed, authority.Outcome);
        Assert.Contains("renewal information", authority.Detail, StringComparison.Ordinal);

        // Pebble runs in a container on the same host, so any difference here is real skew.
        Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(report, "clock").Outcome);

        // Nothing is configured that would make either of these fail against Pebble.
        Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(report, "account-binding").Outcome);
        Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(report, "storage").Outcome);
    }

    [Fact]
    public async Task AProfileRealPebbleOffersIsAccepted()
    {
        using var storage = new TempStorage();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(NewDomain());
            options.StorageDirectory = storage.Path;
            options.Profile = "shortlived";
        });

        AutoHttpsDiagnosticsReport report = await app.Services
            .GetRequiredService<IAutoHttpsDiagnostics>()
            .RunAsync();

        AutoHttpsCheck profile = Find(report, "profile");

        // Pebble advertises its profiles, so this is the real advertised-profile path rather than the
        // skipped one a stub would take.
        Assert.Equal(AutoHttpsCheckOutcome.Passed, profile.Outcome);
    }

    [Fact]
    public async Task AProfileRealPebbleDoesNotOfferIsRejectedBeforeOrdering()
    {
        using var storage = new TempStorage();

        await using PebbleApplication app = await PebbleApplication.StartAsync(_pebble, options =>
        {
            options.DomainNames.Add(NewDomain());
            options.StorageDirectory = storage.Path;
            options.Profile = "not-a-real-profile";
        });

        AutoHttpsDiagnosticsReport report = await app.Services
            .GetRequiredService<IAutoHttpsDiagnostics>()
            .RunAsync();

        Assert.Equal(AutoHttpsCheckOutcome.Failed, Find(report, "profile").Outcome);
    }

    private static AutoHttpsCheck Find(AutoHttpsDiagnosticsReport report, string name) =>
        report.Checks.FirstOrDefault(check => check.Name == name)
        ?? throw new InvalidOperationException($"no '{name}' check in:{Environment.NewLine}{report}");

    private static string NewDomain() => $"t{Guid.NewGuid():N}"[..12] + ".autohttps.test";
}
