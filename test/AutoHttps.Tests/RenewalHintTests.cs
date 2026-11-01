using System;
using AutoHttps.Acme;
using AutoHttps.Hosting;
using Xunit;

namespace AutoHttps.Tests;

/// <summary>
/// Which newOrder failures make AutoHttps order again without the replaces hint. Dropping it for the
/// wrong failure costs a request at best and hides a rate limit at worst, while keeping it for the right
/// one means the certificate is never renewed.
/// </summary>
public sealed class RenewalHintTests
{
    [Theory]
    [InlineData(409, AcmeErrorTypes.AlreadyReplaced)]
    [InlineData(403, AcmeErrorTypes.Unauthorized)]
    [InlineData(400, "urn:ietf:params:acme:error:malformed")]
    [InlineData(404, "urn:ietf:params:acme:error:malformed")]
    public void ARefusalOfTheOrderDropsTheHint(int status, string type) =>
        Assert.True(CertificateAcquirer.IsRenewalRefused(new AcmeException("refused", type, "detail", status)));

    [Fact]
    public void ARateLimitKeepsTheHint() =>
        Assert.False(CertificateAcquirer.IsRenewalRefused(
            new AcmeRateLimitException("slow down", "too many", DateTimeOffset.UtcNow.AddHours(1))));

    [Fact]
    public void AStaleNonceKeepsTheHint() =>
        Assert.False(CertificateAcquirer.IsRenewalRefused(
            new AcmeException("nonce", AcmeErrorTypes.BadNonce, "detail", 400)));

    [Fact]
    public void AnUnknownAccountIsLeftForReRegistration() =>
        Assert.False(CertificateAcquirer.IsRenewalRefused(
            new AcmeException("gone", AcmeErrorTypes.AccountDoesNotExist, "detail", 400)));

    [Theory]
    [InlineData(500)]
    [InlineData(503)]
    public void AServerFailureKeepsTheHint(int status) =>
        Assert.False(CertificateAcquirer.IsRenewalRefused(
            new AcmeException("broken", "urn:ietf:params:acme:error:serverInternal", "detail", status)));

    [Fact]
    public void ARefusedProfileKeepsTheHint() =>
        // draft-ietf-acme-profiles: invalidProfile is about the profile, and an order without the hint
        // would be refused for the same reason.
        Assert.False(CertificateAcquirer.IsRenewalRefused(
            new AcmeException("profile", "urn:ietf:params:acme:error:invalidProfile", "detail", 400)));

    [Fact]
    public void AFailureBeforeAnythingWasSentKeepsTheHint() =>
        Assert.False(CertificateAcquirer.IsRenewalRefused(new AcmeException("the profile is not offered")));
}
