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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TheEmailAddressIsOptional(string? emailAddress)
    {
        // RFC 8555 makes the contact optional, and Let's Encrypt has stored no contact address since
        // June 2025, so requiring one only made people invent an address.
        AutoHttpsOptions options = Valid();
        options.EmailAddress = emailAddress;

        Assert.True(new AutoHttpsOptionsValidator().Validate(null, options).Succeeded);
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

    [Theory]
    [InlineData(1d)]
    [InlineData(-0.5d)]
    [InlineData(1.5d)]
    [InlineData(double.NaN)]
    public void AnExplicitNearExpiryFractionMustBeAProperFraction(double fraction)
    {
        AutoHttpsOptions options = Valid();
        options.NearExpiryWarningFraction = fraction;

        AssertFails(options, "NearExpiryWarningFraction");
    }

    [Fact]
    public void ANearExpiryFractionAtOrAboveTheRenewalThresholdIsRejected()
    {
        // It would report Degraded before renewal had been attempted once, and never clear, so the
        // signal would be useless from the first day rather than wrong only during an outage.
        AutoHttpsOptions options = Valid();
        options.RenewalThreshold = 1d / 3d;
        options.NearExpiryWarningFraction = 1d / 3d;

        AssertFails(options, "NearExpiryWarningFraction");
    }

    [Fact]
    public void ZeroTurnsTheNearExpiryWarningOffRatherThanFailing()
    {
        AutoHttpsOptions options = Valid();
        options.NearExpiryWarningFraction = 0;

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void TheDefaultNearExpiryFractionNeverConflictsWithALoweredThreshold()
    {
        // The default is derived from the threshold rather than fixed, so lowering the threshold
        // cannot turn a valid configuration into a startup failure on upgrade.
        AutoHttpsOptions options = Valid();
        options.RenewalThreshold = 0.05;

        Assert.True(_validator.Validate(null, options).Succeeded);
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
    public void RequiringACertificateOnStartupWithoutAPositiveTimeoutIsRejected()
    {
        AutoHttpsOptions options = Valid();
        options.RequireCertificateOnStartup = true;
        options.StartupCertificateTimeout = TimeSpan.Zero;

        AssertFails(options, "StartupCertificateTimeout");
    }

    [Fact]
    public void TheStartupCertificateTimeoutIsIgnoredWhenTheCertificateIsNotRequired()
    {
        AutoHttpsOptions options = Valid();
        options.RequireCertificateOnStartup = false;
        options.StartupCertificateTimeout = TimeSpan.Zero;

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

    public static TheoryData<string> Durations => new()
    {
        nameof(AutoHttpsOptions.RenewalCheckInterval),
        nameof(AutoHttpsOptions.ValidationTimeout),
        nameof(AutoHttpsOptions.PollInterval),
        nameof(AutoHttpsOptions.InitialRetryDelay),
        nameof(AutoHttpsOptions.MaxRetryDelay),
        nameof(AutoHttpsOptions.DnsPropagationDelay),
        nameof(AutoHttpsOptions.DnsPropagationTimeout),
        nameof(AutoHttpsOptions.StartupCertificateTimeout),
    };

    [Theory]
    [MemberData(nameof(Durations))]
    public void ADurationTooLongToWaitForIsRejectedAtStartup(string name)
    {
        // A wait over about 49.7 days throws inside the timer, and TimeSpan.MaxValue overflows a
        // deadline. Accepting either here would only move the failure into the renewal loop.
        AutoHttpsOptions options = Valid();
        Set(options, name, TimeSpan.MaxValue);

        AssertFails(options, name + " must be at most 30 days");
    }

    [Theory]
    [MemberData(nameof(Durations))]
    public void ADurationAtTheLimitIsAccepted(string name)
    {
        AutoHttpsOptions options = Valid();
        options.MaxRetryDelay = AutoHttpsOptionsValidator.MaxDuration;
        Set(options, name, AutoHttpsOptionsValidator.MaxDuration);

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    private static void Set(AutoHttpsOptions options, string name, TimeSpan value)
    {
        switch (name)
        {
            case nameof(AutoHttpsOptions.RenewalCheckInterval): options.RenewalCheckInterval = value; break;
            case nameof(AutoHttpsOptions.ValidationTimeout): options.ValidationTimeout = value; break;
            case nameof(AutoHttpsOptions.PollInterval): options.PollInterval = value; break;
            case nameof(AutoHttpsOptions.InitialRetryDelay): options.InitialRetryDelay = value; break;
            case nameof(AutoHttpsOptions.MaxRetryDelay): options.MaxRetryDelay = value; break;
            case nameof(AutoHttpsOptions.DnsPropagationDelay): options.DnsPropagationDelay = value; break;
            case nameof(AutoHttpsOptions.DnsPropagationTimeout): options.DnsPropagationTimeout = value; break;
            case nameof(AutoHttpsOptions.StartupCertificateTimeout): options.StartupCertificateTimeout = value; break;
            default: throw new ArgumentOutOfRangeException(nameof(name), name, "Not a duration option.");
        }
    }

    [Fact]
    public void EveryProblemIsReportedAtOnce()
    {
        // No names, the agreement not accepted, and a malformed address.
        var options = new AutoHttpsOptions { EmailAddress = "not-an-address" };

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
