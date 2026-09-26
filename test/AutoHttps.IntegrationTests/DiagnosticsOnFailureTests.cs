using System;
using System.Threading.Tasks;
using AutoHttps.IntegrationTests.TestCa;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// The point of running the diagnostics automatically is that an operator whose first order fails finds
/// the cause in the log rather than only the authority's account of it, without having been told to turn
/// anything on. It has to happen once, not on every retry.
/// </summary>
public class DiagnosticsOnFailureTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    // Somewhere nothing listens, so a validation fails at once rather than after a transport backoff.
    private static readonly Uri Nowhere = new("http://127.0.0.1:1/");

    [Fact]
    public async Task AFailedOrderIsDiagnosedOnceHoweverManyTimesItFails()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        using var storage = new TempStorage();

        await using TestApplication app = await StartAsync(authority, storage, diagnose: true);
        authority.HttpChallengeResolver = _ => Nowhere;

        await WaitForAsync(app, () => app.Log.CountOf(144) > 0, "the failure was never diagnosed");
        await WaitForAsync(app, () => app.Log.CountOf(110) >= 2, "the order did not fail more than once");

        Assert.Equal(1, app.Log.CountOf(144));
    }

    [Fact]
    public async Task TurningTheDiagnosisOffKeepsItOutOfTheLog()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        using var storage = new TempStorage();

        await using TestApplication app = await StartAsync(authority, storage, diagnose: false);
        authority.HttpChallengeResolver = _ => Nowhere;

        await WaitForAsync(app, () => app.Log.CountOf(110) >= 2, "the order did not fail");

        Assert.Equal(0, app.Log.CountOf(144));
        Assert.Equal(0, app.Log.CountOf(145));
    }

    [Fact]
    public async Task TheReportNamesTheChallengePathThatNothingAnswered()
    {
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        using var storage = new TempStorage();

        await using TestApplication app = await StartAsync(authority, storage, diagnose: true);
        authority.HttpChallengeResolver = _ => Nowhere;

        await WaitForAsync(app, () => app.Log.CountOf(144) > 0, "the failure was never diagnosed");

        string log = app.Log.Describe(200);

        // The authority itself is reachable here, so what the report has to surface is the part that is
        // not: the challenge path, along with the checks that did run.
        Assert.Contains("challenge-path", log, StringComparison.Ordinal);
        Assert.Contains("storage", log, StringComparison.Ordinal);
    }

    private static Task<TestApplication> StartAsync(
        TestCertificateAuthority authority,
        TempStorage storage,
        bool diagnose) =>
        TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.DiagnoseOrderFailures = diagnose;
        });

    private static async Task WaitForAsync(TestApplication app, Func<bool> condition, string failure)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + Timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException(failure + ":" + Environment.NewLine + app.Log.Describe(200));
    }
}
