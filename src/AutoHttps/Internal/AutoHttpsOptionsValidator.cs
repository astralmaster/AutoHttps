using System;
using System.Collections.Generic;
using System.Globalization;
using AutoHttps.Challenges;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AutoHttps.Internal;

internal sealed class AutoHttpsOptionsValidator : IValidateOptions<AutoHttpsOptions>
{
    private readonly IServiceProviderIsService? _registrations;

    public AutoHttpsOptionsValidator()
    {
    }

    /// <summary>
    /// A DNS provider can be supplied either on the options or through the service collection, so
    /// the validator has to know about both. Registration is probed rather than resolved, which
    /// keeps a provider that itself depends on these options from being constructed mid-validation.
    /// </summary>
    /// <param name="registrations">The container's registration lookup.</param>
    public AutoHttpsOptionsValidator(IServiceProviderIsService registrations) => _registrations = registrations;

    public ValidateOptionsResult Validate(string? name, AutoHttpsOptions options)
    {
        var failures = new List<string>();

        if (options.DomainNames.Count == 0)
        {
            failures.Add($"{nameof(AutoHttpsOptions.DomainNames)} must contain at least one domain.");
        }

        bool hasWildcard = false;
        foreach (string domain in options.DomainNames)
        {
            if (!DomainNormalizer.TryNormalize(domain, out string normalized))
            {
                failures.Add($"'{domain}' is not a valid domain name or IP address.");
                continue;
            }

            hasWildcard |= DomainNormalizer.IsWildcard(normalized);
        }

        if (string.IsNullOrWhiteSpace(options.EmailAddress))
        {
            failures.Add($"{nameof(AutoHttpsOptions.EmailAddress)} is required. Certificate authorities use it to contact you about your account.");
        }
        else if (!IsPlausibleEmail(options.EmailAddress))
        {
            failures.Add($"'{options.EmailAddress}' is not a valid email address.");
        }

        if (!options.AcceptTermsOfService)
        {
            failures.Add(
                $"{nameof(AutoHttpsOptions.AcceptTermsOfService)} must be set to true. " +
                "Read the subscriber agreement published by your certificate authority before enabling it.");
        }

        if (options.CertificateAuthority is null || !options.CertificateAuthority.IsAbsoluteUri)
        {
            failures.Add($"{nameof(AutoHttpsOptions.CertificateAuthority)} must be an absolute URI pointing at an ACME directory.");
        }
        else if (options.CertificateAuthority.Scheme is not ("https" or "http"))
        {
            failures.Add(
                $"{nameof(AutoHttpsOptions.CertificateAuthority)} must use https, but '{options.CertificateAuthority}' uses " +
                $"'{options.CertificateAuthority.Scheme}'. Only a local test server should ever use http.");
        }

        if (options.PreferredChallengeType is not (ChallengeTypes.Http01 or ChallengeTypes.Dns01))
        {
            failures.Add(
                $"{nameof(AutoHttpsOptions.PreferredChallengeType)} must be '{ChallengeTypes.Http01}' or '{ChallengeTypes.Dns01}'.");
        }

        bool hasDnsProvider = HasDnsProvider(options);

        if (hasWildcard && !hasDnsProvider)
        {
            failures.Add(
                $"A wildcard domain requires {nameof(AutoHttpsOptions.DnsChallengeProvider)} to be set, " +
                "because a certificate authority will only validate a wildcard with a dns-01 challenge.");
        }

        if (options.PreferredChallengeType == ChallengeTypes.Dns01 && !hasDnsProvider)
        {
            failures.Add(
                $"{nameof(AutoHttpsOptions.PreferredChallengeType)} is '{ChallengeTypes.Dns01}' but no " +
                $"{nameof(AutoHttpsOptions.DnsChallengeProvider)} was supplied.");
        }

        if (options.RenewalThreshold is <= 0 or >= 1)
        {
            failures.Add($"{nameof(AutoHttpsOptions.RenewalThreshold)} must be greater than 0 and less than 1.");
        }

        RequirePositive(failures, options.RenewalCheckInterval, nameof(AutoHttpsOptions.RenewalCheckInterval));
        RequirePositive(failures, options.ValidationTimeout, nameof(AutoHttpsOptions.ValidationTimeout));
        RequirePositive(failures, options.PollInterval, nameof(AutoHttpsOptions.PollInterval));
        RequirePositive(failures, options.InitialRetryDelay, nameof(AutoHttpsOptions.InitialRetryDelay));
        RequirePositive(failures, options.MaxRetryDelay, nameof(AutoHttpsOptions.MaxRetryDelay));

        if (options.DnsPropagationDelay < TimeSpan.Zero)
        {
            failures.Add($"{nameof(AutoHttpsOptions.DnsPropagationDelay)} cannot be negative.");
        }

        if (options.MaxRetryDelay < options.InitialRetryDelay)
        {
            failures.Add(
                $"{nameof(AutoHttpsOptions.MaxRetryDelay)} must be greater than or equal to " +
                $"{nameof(AutoHttpsOptions.InitialRetryDelay)}.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private bool HasDnsProvider(AutoHttpsOptions options) =>
        options.DnsChallengeProvider is not null || (_registrations?.IsService(typeof(IDnsChallengeProvider)) ?? false);

    private static void RequirePositive(List<string> failures, TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero)
        {
            failures.Add(string.Create(CultureInfo.InvariantCulture, $"{name} must be greater than zero."));
        }
    }

    private static bool IsPlausibleEmail(string value)
    {
        int at = value.IndexOf('@', StringComparison.Ordinal);
        if (at <= 0 || at == value.Length - 1)
        {
            return false;
        }

        if (value.IndexOf('@', at + 1) >= 0)
        {
            return false;
        }

        ReadOnlySpan<char> domain = value.AsSpan(at + 1);
        return domain.Contains('.') && !domain.Contains(' ') && !value.AsSpan(0, at).Contains(' ');
    }
}
