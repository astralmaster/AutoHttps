using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Challenges;
using AutoHttps.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.Tests;

public class OptionsValidatorTests
{
    private readonly AutoHttpsOptionsValidator _validator = new();

    [Fact]
    public void AWellFormedConfigurationIsAccepted() =>
        Assert.True(_validator.Validate(null, Valid()).Succeeded);

    [Fact]
    public void DomainsAreRequired()
    {
        AutoHttpsOptions options = Valid();
        options.DomainNames.Clear();

        AssertFails(options, "DomainNames");
    }

    [Fact]
    public void AnInvalidDomainIsReported()
    {
        AutoHttpsOptions options = Valid();
        options.DomainNames.Add("not a domain");

        AssertFails(options, "not a domain");
    }

    [Fact]
    public void TheEmailAddressIsRequired()
    {
        AutoHttpsOptions options = Valid();
        options.EmailAddress = null;

        AssertFails(options, "EmailAddress");
    }

    [Theory]
    [InlineData("nope")]
    [InlineData("@example.com")]
    [InlineData("me@")]
    [InlineData("me@example")]
    [InlineData("a@b@example.com")]
    [InlineData("me @example.com")]
    public void AMalformedEmailAddressIsReported(string emailAddress)
    {
        AutoHttpsOptions options = Valid();
        options.EmailAddress = emailAddress;

        AssertFails(options, "not a valid email");
    }

    [Fact]
    public void TheTermsOfServiceMustBeAccepted()
    {
        AutoHttpsOptions options = Valid();
        options.AcceptTermsOfService = false;

        AssertFails(options, "AcceptTermsOfService");
    }

    [Fact]
    public void AWildcardWithoutADnsProviderIsRejected()
    {
        AutoHttpsOptions options = Valid();
        options.DomainNames.Add("*.example.com");

        AssertFails(options, "dns-01");
    }

    [Fact]
    public void AWildcardWithADnsProviderIsAccepted()
    {
        AutoHttpsOptions options = Valid();
        options.DomainNames.Add("*.example.com");
        options.DnsChallengeProvider = new StubDnsProvider();

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void ADnsProviderRegisteredInTheContainerSatisfiesTheWildcardRequirement()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IDnsChallengeProvider, StubDnsProvider>();

        using ServiceProvider provider = services.BuildServiceProvider();
        var validator = new AutoHttpsOptionsValidator(provider.GetRequiredService<IServiceProviderIsService>());

        AutoHttpsOptions options = Valid();
        options.DomainNames.Add("*.example.com");
        options.PreferredChallengeType = ChallengeTypes.Dns01;

        Assert.True(validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void AnEmptyContainerDoesNotSatisfyTheWildcardRequirement()
    {
        var services = new ServiceCollection();

        using ServiceProvider provider = services.BuildServiceProvider();
        var validator = new AutoHttpsOptionsValidator(provider.GetRequiredService<IServiceProviderIsService>());

        AutoHttpsOptions options = Valid();
        options.DomainNames.Add("*.example.com");

        Assert.True(validator.Validate(null, options).Failed);
    }

    [Fact]
    public void PreferringDnsWithoutAProviderIsRejected()
    {
        AutoHttpsOptions options = Valid();
        options.PreferredChallengeType = ChallengeTypes.Dns01;

        AssertFails(options, "DnsChallengeProvider");
    }

    [Fact]
    public void AnUnknownChallengeTypeIsRejected()
    {
        AutoHttpsOptions options = Valid();
        options.PreferredChallengeType = "tls-alpn-01";

        AssertFails(options, "PreferredChallengeType");
    }

    [Theory]
    [InlineData(0d)]
    [InlineData(1d)]
    [InlineData(-0.5d)]
    [InlineData(1.5d)]
    public void TheRenewalThresholdMustBeAProperFraction(double threshold)
    {
        AutoHttpsOptions options = Valid();
        options.RenewalThreshold = threshold;

        AssertFails(options, "RenewalThreshold");
    }

    [Fact]
    public void NonPositiveIntervalsAreRejected()
    {
        AutoHttpsOptions options = Valid();
        options.RenewalCheckInterval = TimeSpan.Zero;
        options.PollInterval = TimeSpan.FromSeconds(-1);

        ValidateOptionsResult result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("RenewalCheckInterval", StringComparison.Ordinal));
        Assert.Contains(result.Failures!, f => f.Contains("PollInterval", StringComparison.Ordinal));
    }

    [Fact]
    public void ANegativeDnsPropagationDelayIsRejected()
    {
        AutoHttpsOptions options = Valid();
        options.DnsPropagationDelay = TimeSpan.FromSeconds(-1);

        AssertFails(options, "DnsPropagationDelay");
    }

    [Fact]
    public void AZeroDnsPropagationDelayIsAllowed()
    {
        AutoHttpsOptions options = Valid();
        options.DnsPropagationDelay = TimeSpan.Zero;

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void AMaxRetryDelayBelowTheInitialOneIsRejected()
    {
        AutoHttpsOptions options = Valid();
        options.InitialRetryDelay = TimeSpan.FromMinutes(10);
        options.MaxRetryDelay = TimeSpan.FromMinutes(1);

        AssertFails(options, "MaxRetryDelay");
    }

    [Fact]
    public void ARelativeCertificateAuthorityUriIsRejected()
    {
        AutoHttpsOptions options = Valid();
        options.CertificateAuthority = new Uri("/directory", UriKind.Relative);

        AssertFails(options, "CertificateAuthority");
    }

    [Theory]
    [InlineData("ftp://acme.example.com/directory")]
    [InlineData("file:///c:/directory.json")]
    [InlineData("acme://acme.example.com/directory")]
    public void ACertificateAuthorityThatIsNotReachableOverHttpIsRejected(string uri)
    {
        // Left unchecked this only surfaces at runtime, one failed order at a time.
        AutoHttpsOptions options = Valid();
        options.CertificateAuthority = new Uri(uri);

        AssertFails(options, "CertificateAuthority");
    }

    [Theory]
    [InlineData("https://acme.example.com/directory")]
    [InlineData("http://localhost:14000/dir")]
    public void HttpAndHttpsCertificateAuthoritiesAreAccepted(string uri)
    {
        AutoHttpsOptions options = Valid();
        options.CertificateAuthority = new Uri(uri);

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void EveryProblemIsReportedAtOnce()
    {
        var options = new AutoHttpsOptions();

        ValidateOptionsResult result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.True(result.Failures!.Count() >= 3, "The validator should report all problems, not just the first.");
    }

    private void AssertFails(AutoHttpsOptions options, string expectedFragment)
    {
        ValidateOptionsResult result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, failure => failure.Contains(expectedFragment, StringComparison.OrdinalIgnoreCase));
    }

    private static AutoHttpsOptions Valid()
    {
        var options = new AutoHttpsOptions
        {
            EmailAddress = "operator@example.com",
            AcceptTermsOfService = true,
        };

        options.DomainNames.Add("example.com");
        return options;
    }

    private sealed class StubDnsProvider : IDnsChallengeProvider
    {
        public Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
