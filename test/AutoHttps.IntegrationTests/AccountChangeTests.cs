using System;
using System.IO;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Xunit;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// The account is keyed by the email address and the certificate by the domains, so changing the
/// address, or losing the account key, leaves a stored certificate that a different account now has
/// to renew. Authorities refuse a renewal hint naming another account's certificate, and a client
/// that keeps sending it never renews again.
/// </summary>
public sealed class AccountChangeTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task ACertificateFromThePreviousAccountIsStillRenewedAfterTheEmailAddressChanges()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.CertificateLifetime = TimeSpan.FromMinutes(10);

        string original = await IssueAsync(authority, storage, "first@example.com");

        await using TestApplication second = await StartDueAsync(authority, storage, "second@example.com");
        ServerCertificate renewed = await second.WaitForCertificateChangeAsync("app.example.com", original, IssuanceTimeout);

        AssertRecoveredByDroppingTheHint(authority, second, original, renewed);
        Assert.Equal(2, authority.AccountCount);
    }

    [Fact]
    public async Task ACertificateIsStillRenewedAfterTheAccountKeyIsLost()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.CertificateLifetime = TimeSpan.FromMinutes(10);

        string original = await IssueAsync(authority, storage, "operator@example.com");

        // A restore that brought back the certificates but not the account key, or a store that keeps
        // them in different places.
        foreach (string accountKey in Directory.GetFiles(storage.Path, "*.account.pem"))
        {
            File.Delete(accountKey);
        }

        await using TestApplication second = await StartDueAsync(authority, storage, "operator@example.com");
        ServerCertificate renewed = await second.WaitForCertificateChangeAsync("app.example.com", original, IssuanceTimeout);

        AssertRecoveredByDroppingTheHint(authority, second, original, renewed);
    }

    private static async Task<string> IssueAsync(TestCertificateAuthority authority, TempStorage storage, string email)
    {
        await using TestApplication first = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.EmailAddress = email;
        });

        return (await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout)).Leaf.Thumbprint;
    }

    // The stored certificate is due the moment it is loaded: a threshold this close to 1 puts the
    // renewal point under a second into a ten minute lifetime. Renewal information is not consulted,
    // so the threshold alone decides, but the directory still advertises it and so the order carries
    // the replaces hint naming the stored certificate.
    private static Task<TestApplication> StartDueAsync(TestCertificateAuthority authority, TempStorage storage, string email) =>
        TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.EmailAddress = email;
            options.UseRenewalInformation = false;
            options.RenewalThreshold = 0.999;
        });

    private static void AssertRecoveredByDroppingTheHint(
        TestCertificateAuthority authority,
        TestApplication app,
        string original,
        ServerCertificate renewed)
    {
        Assert.NotEqual(original, renewed.Leaf.Thumbprint);

        // The authority really refused the hint, so this exercised the refusal and not a lucky order
        // that never named the old certificate.
        Assert.True(authority.SawReplaces, "No order named the stored certificate in replaces.");
        Assert.True(authority.RefusedReplaces > 0, "The authority never refused the replaces hint.");

        // The recovery happens inside the same attempt, so no attempt is reported as failed.
        Assert.True(app.Log.CountOf(148) > 0, "The refused hint was not reported." + Environment.NewLine + app.Log.Describe());
        Assert.Equal(0, app.Log.CountOf(110));
    }
}
