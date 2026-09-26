using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Certificates;
using AutoHttps.Challenges;
using AutoHttps.Internal;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Options;

namespace AutoHttps.Diagnostics;

/// <summary>
/// Runs the checks behind <see cref="IAutoHttpsDiagnostics"/>. Every one is read only: nothing here
/// orders, renews or changes what is served.
/// </summary>
internal sealed class AutoHttpsDiagnostics : IAutoHttpsDiagnostics
{
    private static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan SelfCheckTimeout = TimeSpan.FromSeconds(10);

    private readonly AutoHttpsOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly DnsLookup _dns;
    private readonly IHttp01ChallengeStore _challenges;
    private readonly ICertificateStore _certificates;
    private readonly IEnumerable<IServer> _servers;
    private readonly TimeProvider _time;

    public AutoHttpsDiagnostics(
        IOptions<AutoHttpsOptions> options,
        IHttpClientFactory httpClientFactory,
        DnsLookup dns,
        IHttp01ChallengeStore challenges,
        ICertificateStore certificates,
        IEnumerable<IServer> servers,
        TimeProvider time)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _dns = dns;
        _challenges = challenges;
        _certificates = certificates;
        _servers = servers;
        _time = time;
    }

    public async Task<AutoHttpsDiagnosticsReport> RunAsync(CancellationToken cancellationToken = default)
    {
        var checks = new List<AutoHttpsCheck>();
        IReadOnlyList<string> domains = DomainNormalizer.Normalize(_options.DomainNames);

        checks.Add(CheckConfiguration(domains));
        checks.Add(CheckStorage());
        checks.Add(CheckListener());

        AcmeDirectory? directory = await CheckAuthorityAsync(checks, cancellationToken);

        await CheckDnsAsync(checks, domains, cancellationToken);
        await CheckCaaAsync(checks, domains, directory, cancellationToken);
        await CheckChallengePathAsync(checks, domains, cancellationToken);

        return new AutoHttpsDiagnosticsReport(checks);
    }

    /// <summary>
    /// The limits that depend only on what is configured, which the authority would otherwise report as
    /// a rejected order.
    /// </summary>
    private AutoHttpsCheck CheckConfiguration(IReadOnlyList<string> domains)
    {
        var problems = new List<string>();
        var remedies = new List<string>();

        if (ProfileLimits.MaxIdentifiers(_options.Profile) is { } maximum && domains.Count > maximum)
        {
            problems.Add(string.Create(
                CultureInfo.InvariantCulture,
                $"{domains.Count} names is more than the {maximum} the '{_options.Profile}' profile allows"));
            remedies.Add("split the names across more than one certificate, or choose a profile with a higher limit");
        }

        string[] addresses = [.. domains.Where(static domain => IPAddress.TryParse(domain, out _))];
        if (addresses.Length > 0)
        {
            if (!ProfileLimits.AllowsIpIdentifiers(_options.Profile))
            {
                problems.Add($"an IP address identifier ({addresses[0]}) needs the '{CertificateProfiles.ShortLived}' profile");
                remedies.Add($"set Profile to CertificateProfiles.ShortLived, which is the only profile that carries an IP address");
            }

            if (_options.PreferredChallengeType == ChallengeTypes.Dns01)
            {
                problems.Add("an IP address cannot be validated by dns-01");
                remedies.Add($"set PreferredChallengeType to '{ChallengeTypes.Http01}' for an IP address");
            }
        }

        string summary = string.Create(
            CultureInfo.InvariantCulture,
            $"{domains.Count} name(s), profile '{_options.Profile ?? "(authority default)"}', challenge '{_options.PreferredChallengeType}'");

        return problems.Count == 0
            ? new AutoHttpsCheck("configuration", AutoHttpsCheckOutcome.Passed, summary)
            : new AutoHttpsCheck(
                "configuration",
                AutoHttpsCheckOutcome.Warning,
                summary + ". " + string.Join("; ", problems),
                string.Join("; ", remedies));
    }

    /// <summary>
    /// Whether the certificate can actually be written. A directory inside a container that is not a
    /// mounted volume reads as writable here and is still lost on restart, which no check can see, so
    /// this only rules out the case where it cannot be written at all.
    /// </summary>
    private AutoHttpsCheck CheckStorage()
    {
        if (_certificates is not FileSystemStore)
        {
            return new AutoHttpsCheck(
                "storage",
                AutoHttpsCheckOutcome.Skipped,
                $"a {_certificates.GetType().Name} is in use, which this cannot probe");
        }

        string directory = AutoHttpsServiceCollectionExtensions.ResolveStorageDirectory(_options);
        string probe = Path.Combine(directory, "autohttps-writable-" + Guid.NewGuid().ToString("n") + ".tmp");

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);

            return new AutoHttpsCheck("storage", AutoHttpsCheckOutcome.Passed, $"'{directory}' is writable");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return new AutoHttpsCheck(
                "storage",
                AutoHttpsCheckOutcome.Failed,
                $"'{directory}' cannot be written: {ex.Message}",
                "point StorageDirectory at a writable, durable location; without one every restart orders again " +
                "and runs into the authority's duplicate-certificate limit");
        }
    }

    /// <summary>
    /// An http-01 validation always starts on port 80. Not listening there is only a warning, because a
    /// proxy forwarding 80 to another port is both valid and common.
    /// </summary>
    private AutoHttpsCheck CheckListener()
    {
        if (_options.PreferredChallengeType != ChallengeTypes.Http01)
        {
            return new AutoHttpsCheck(
                "port-80",
                AutoHttpsCheckOutcome.Skipped,
                $"the preferred challenge is '{_options.PreferredChallengeType}', which does not use port 80");
        }

        IServerAddressesFeature? feature = _servers.FirstOrDefault()?.Features.Get<IServerAddressesFeature>();
        if (feature is null)
        {
            return new AutoHttpsCheck("port-80", AutoHttpsCheckOutcome.Skipped, "the server's addresses are not available");
        }

        string[] addresses = [.. feature.Addresses];
        if (addresses.Length == 0)
        {
            return new AutoHttpsCheck("port-80", AutoHttpsCheckOutcome.Skipped, "the server has not bound an address yet");
        }

        bool listening = addresses.Any(static address =>
            Uri.TryCreate(address, UriKind.Absolute, out Uri? parsed) && parsed.Port == 80);

        return listening
            ? new AutoHttpsCheck("port-80", AutoHttpsCheckOutcome.Passed, "bound to port 80")
            : new AutoHttpsCheck(
                "port-80",
                AutoHttpsCheckOutcome.Warning,
                "nothing is bound to port 80; this process listens on " + string.Join(", ", addresses),
                "an http-01 validation always starts on port 80, so either publish it to this process or " +
                "forward it here. The .NET container images listen on 8080 as a non-root user and cannot " +
                "bind 80 themselves, so the port has to be mapped");
    }

    /// <summary>
    /// One request to the directory answers several questions at once: whether the authority is
    /// reachable, what the clock difference is, whether an account binding is required, and whether the
    /// requested profile exists.
    /// </summary>
    private async Task<AcmeDirectory?> CheckAuthorityAsync(List<AutoHttpsCheck> checks, CancellationToken cancellationToken)
    {
        Uri? authority = _options.CertificateAuthority;
        if (authority is null)
        {
            checks.Add(new AutoHttpsCheck("authority", AutoHttpsCheckOutcome.Failed, "no CertificateAuthority is configured"));
            return null;
        }

        HttpResponseMessage response;
        string body;

        try
        {
            using HttpClient client = _httpClientFactory.CreateClient(AutoHttpsDefaults.HttpClientName);
            response = await client.GetAsync(authority, cancellationToken);
            body = await response.Content.ReadAsStringAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            checks.Add(new AutoHttpsCheck(
                "authority",
                AutoHttpsCheckOutcome.Failed,
                $"'{authority}' could not be reached: {ex.Message}",
                "check outbound access and, if a proxy inspects TLS or the authority uses a private root, " +
                "configure the named HttpClient AutoHttpsDefaults.HttpClientName"));
            return null;
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                checks.Add(new AutoHttpsCheck(
                    "authority",
                    AutoHttpsCheckOutcome.Failed,
                    string.Create(CultureInfo.InvariantCulture, $"'{authority}' answered {(int)response.StatusCode}"),
                    "check that CertificateAuthority points at an ACME directory"));
                return null;
            }

            AcmeDirectory? directory = TryParseDirectory(body);
            if (directory is null)
            {
                checks.Add(new AutoHttpsCheck(
                    "authority",
                    AutoHttpsCheckOutcome.Failed,
                    $"'{authority}' answered something that is not an ACME directory",
                    "check that CertificateAuthority points at the directory URL, not at the website"));
                return null;
            }

            checks.Add(new AutoHttpsCheck(
                "authority",
                AutoHttpsCheckOutcome.Passed,
                $"'{authority}' is reachable and " + (directory.RenewalInfo is not null
                    ? "offers renewal information, so renewals are exempt from rate limits"
                    : "does not offer renewal information")));

            checks.Add(CheckClock(response.Headers.Date));
            checks.Add(CheckAccountBinding(directory));

            if (CheckProfile(directory) is { } profile)
            {
                checks.Add(profile);
            }

            return directory;
        }
    }

    /// <summary>
    /// A skewed clock breaks ACME in a way that reads as nothing in particular: signatures are rejected
    /// and a freshly issued certificate can look as though it is not valid yet.
    /// </summary>
    private AutoHttpsCheck CheckClock(DateTimeOffset? authorityTime)
    {
        if (authorityTime is not { } reported)
        {
            return new AutoHttpsCheck("clock", AutoHttpsCheckOutcome.Skipped, "the authority did not return a Date header");
        }

        TimeSpan skew = _time.GetUtcNow() - reported;
        TimeSpan magnitude = skew < TimeSpan.Zero ? -skew : skew;

        return magnitude <= MaxClockSkew
            ? new AutoHttpsCheck(
                "clock",
                AutoHttpsCheckOutcome.Passed,
                string.Create(CultureInfo.InvariantCulture, $"within {(int)magnitude.TotalSeconds}s of the authority"))
            : new AutoHttpsCheck(
                "clock",
                AutoHttpsCheckOutcome.Warning,
                string.Create(CultureInfo.InvariantCulture, $"this host is {(int)skew.TotalSeconds}s from the authority"),
                "synchronise the clock; a large difference makes the authority reject request signatures and can " +
                "make a new certificate look as though it is not valid yet");
    }

    private AutoHttpsCheck CheckAccountBinding(AcmeDirectory directory)
    {
        bool required = directory.Meta?.ExternalAccountRequired ?? false;

        if (required && _options.ExternalAccountBinding is null)
        {
            return new AutoHttpsCheck(
                "account-binding",
                AutoHttpsCheckOutcome.Failed,
                "this authority requires external account binding and none is configured",
                "set ExternalAccountBinding to the key id and HMAC key from the authority's account page");
        }

        return new AutoHttpsCheck(
            "account-binding",
            AutoHttpsCheckOutcome.Passed,
            required ? "required and configured" : "not required by this authority");
    }

    private AutoHttpsCheck? CheckProfile(AcmeDirectory directory)
    {
        if (string.IsNullOrEmpty(_options.Profile))
        {
            return null;
        }

        IReadOnlyDictionary<string, string>? advertised = directory.Meta?.Profiles;
        if (advertised is null || advertised.Count == 0)
        {
            return new AutoHttpsCheck(
                "profile",
                AutoHttpsCheckOutcome.Skipped,
                $"'{_options.Profile}' was requested and this authority advertises no profiles, so it may be ignored");
        }

        return advertised.ContainsKey(_options.Profile)
            ? new AutoHttpsCheck("profile", AutoHttpsCheckOutcome.Passed, $"'{_options.Profile}' is offered")
            : new AutoHttpsCheck(
                "profile",
                AutoHttpsCheckOutcome.Failed,
                $"'{_options.Profile}' is not offered; this authority offers {string.Join(", ", advertised.Keys)}",
                "set Profile to one the authority offers, or leave it unset for the default");
    }

    /// <summary>
    /// The check that answers the most common unexplained failure. A resolver that validates DNSSEC
    /// answers SERVFAIL for a name whose chain is broken, while an ordinary lookup from the same host
    /// succeeds, so the name looks fine to its owner and is unresolvable to the authority.
    /// </summary>
    private async Task CheckDnsAsync(
        List<AutoHttpsCheck> checks,
        IReadOnlyList<string> domains,
        CancellationToken cancellationToken)
    {
        if (_options.DnsPropagationResolver is not { } resolver)
        {
            checks.Add(new AutoHttpsCheck(
                "dns",
                AutoHttpsCheckOutcome.Skipped,
                "no DnsPropagationResolver is configured, and AutoHttps makes no DNS queries of its own without one",
                "set DnsPropagationResolver, for example https://dns.google/resolve, to enable the DNS checks"));
            return;
        }

        foreach (string domain in domains)
        {
            if (IPAddress.TryParse(domain, out _))
            {
                continue;
            }

            string name = domain.StartsWith("*.", StringComparison.Ordinal) ? domain[2..] : domain;
            checks.Add(await CheckOneNameAsync(resolver, name, cancellationToken));
        }
    }

    private async Task<AutoHttpsCheck> CheckOneNameAsync(Uri resolver, string name, CancellationToken cancellationToken)
    {
        string check = "dns:" + name;

        DnsLookupResult? a = await _dns.QueryAsync(resolver, name, DnsRecordType.A, cancellationToken);
        if (a is not { } address)
        {
            return new AutoHttpsCheck(check, AutoHttpsCheckOutcome.Warning, $"'{resolver}' could not be reached");
        }

        if (address.Status == DnsLookup.ServerFailure)
        {
            return new AutoHttpsCheck(
                check,
                AutoHttpsCheckOutcome.Failed,
                "the resolver answered SERVFAIL, so it could not resolve this name at all",
                "a broken DNSSEC chain is the usual cause, and the authority's resolvers validate DNSSEC even " +
                "though an ordinary lookup from this host may succeed. Check the name on dnsviz.net and fix or " +
                "remove DNSSEC at the DNS provider. A provider that answers non-authoritatively or refuses TCP " +
                "fails the same way");
        }

        if (address.Status == DnsLookup.NameError)
        {
            return new AutoHttpsCheck(
                check,
                AutoHttpsCheckOutcome.Failed,
                "no such name (NXDOMAIN)",
                "publish an A record for this name pointing at this host");
        }

        if (address.Records.Count == 0)
        {
            return new AutoHttpsCheck(
                check,
                AutoHttpsCheckOutcome.Failed,
                string.Create(CultureInfo.InvariantCulture, $"the name resolved with status {address.Status} but returned no A record"),
                "publish an A record for this name pointing at this host");
        }

        // A name with no AAAA record is ordinary and is reported as such, because the NXDOMAIN a resolver
        // returns for the missing AAAA is the line people mistake for the cause of a failure.
        DnsLookupResult? aaaa = await _dns.QueryAsync(resolver, name, DnsRecordType.Aaaa, cancellationToken);
        string sixth = aaaa is { Records.Count: > 0 } found
            ? "AAAA " + string.Join(", ", found.Records)
            : "no AAAA record, which is normal";

        string dnssec = address.AuthenticatedData ? "DNSSEC validated" : "no DNSSEC";

        return new AutoHttpsCheck(
            check,
            AutoHttpsCheckOutcome.Passed,
            $"A {string.Join(", ", address.Records)}; {sixth}; {dnssec}");
    }

    /// <summary>
    /// CAA records that do not name the authority stop issuance with an error that says little. This
    /// only reports: the authority performs the authoritative check, from several perspectives.
    /// </summary>
    private async Task CheckCaaAsync(
        List<AutoHttpsCheck> checks,
        IReadOnlyList<string> domains,
        AcmeDirectory? directory,
        CancellationToken cancellationToken)
    {
        if (_options.DnsPropagationResolver is not { } resolver)
        {
            return;
        }

        IReadOnlyList<string>? identities = directory?.Meta?.CaaIdentities;
        if (identities is null || identities.Count == 0)
        {
            checks.Add(new AutoHttpsCheck(
                "caa",
                AutoHttpsCheckOutcome.Skipped,
                "the authority does not publish caaIdentities, so CAA records cannot be compared against it"));
            return;
        }

        foreach (string domain in domains)
        {
            if (IPAddress.TryParse(domain, out _))
            {
                continue;
            }

            bool wildcard = domain.StartsWith("*.", StringComparison.Ordinal);
            string name = wildcard ? domain[2..] : domain;

            checks.Add(await CheckOneCaaAsync(resolver, name, wildcard, identities, cancellationToken));
        }
    }

    private async Task<AutoHttpsCheck> CheckOneCaaAsync(
        Uri resolver,
        string name,
        bool wildcard,
        IReadOnlyList<string> identities,
        CancellationToken cancellationToken)
    {
        string check = "caa:" + name;

        // RFC 8659 section 3: the closest ancestor with a CAA record set owns the policy, so the tree is
        // climbed until one is found. Stopping above the last two labels avoids asking about a TLD.
        for (string candidate = name; candidate.Contains('.', StringComparison.Ordinal); candidate = Parent(candidate))
        {
            DnsLookupResult? result = await _dns.QueryAsync(resolver, candidate, DnsRecordType.Caa, cancellationToken);
            if (result is not { } records)
            {
                return new AutoHttpsCheck(check, AutoHttpsCheckOutcome.Warning, $"'{resolver}' could not be reached");
            }

            if (records.Records.Count == 0)
            {
                continue;
            }

            CaaVerdict verdict = CaaPolicy.Evaluate(records.Records, identities, wildcard);

            return verdict switch
            {
                CaaVerdict.Permitted => new AutoHttpsCheck(
                    check,
                    AutoHttpsCheckOutcome.Passed,
                    $"the CAA records on '{candidate}' permit {string.Join(" or ", identities)}"),
                CaaVerdict.Forbidden => new AutoHttpsCheck(
                    check,
                    AutoHttpsCheckOutcome.Failed,
                    $"the CAA records on '{candidate}' do not permit {string.Join(" or ", identities)}: " +
                    string.Join("; ", records.Records),
                    $"add a CAA record permitting this authority, for example '0 issue \"{identities[0]}\"', or " +
                    "remove the ones that exclude it"),
                _ => new AutoHttpsCheck(
                    check,
                    AutoHttpsCheckOutcome.Passed,
                    $"the CAA records on '{candidate}' do not restrict issuance"),
            };
        }

        return new AutoHttpsCheck(check, AutoHttpsCheckOutcome.Passed, "no CAA records, so any authority may issue");
    }

    private static string Parent(string name)
    {
        int dot = name.IndexOf('.', StringComparison.Ordinal);
        return dot < 0 ? name : name[(dot + 1)..];
    }

    /// <summary>
    /// Publishes a token of its own and fetches it back over the public name, which is the only check
    /// that exercises the whole path the authority takes.
    /// </summary>
    private async Task CheckChallengePathAsync(
        List<AutoHttpsCheck> checks,
        IReadOnlyList<string> domains,
        CancellationToken cancellationToken)
    {
        if (_options.PreferredChallengeType != ChallengeTypes.Http01)
        {
            checks.Add(new AutoHttpsCheck(
                "challenge-path",
                AutoHttpsCheckOutcome.Skipped,
                $"the preferred challenge is '{_options.PreferredChallengeType}'"));
            return;
        }

        string[] names = [.. domains.Where(static domain =>
            !IPAddress.TryParse(domain, out _) && !domain.StartsWith("*.", StringComparison.Ordinal))];

        if (names.Length == 0)
        {
            checks.Add(new AutoHttpsCheck(
                "challenge-path",
                AutoHttpsCheckOutcome.Skipped,
                "no name that an http-01 validation could reach is configured"));
            return;
        }

        string token = "autohttps-selfcheck-" + Guid.NewGuid().ToString("n");
        string expected = token + ".selfcheck";

        try
        {
            await _challenges.AddAsync(token, expected, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            checks.Add(new AutoHttpsCheck(
                "challenge-path",
                AutoHttpsCheckOutcome.Failed,
                "the challenge store could not be written: " + ex.Message,
                "a shared challenge store that cannot be written means no replica can answer a validation"));
            return;
        }

        try
        {
            foreach (string name in names)
            {
                checks.Add(await FetchOwnTokenAsync(name, token, expected, cancellationToken));
            }
        }
        finally
        {
            try
            {
                await _challenges.RemoveAsync(token, CancellationToken.None);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // The token expires on its own in any store that can expire, and it answers only itself.
            }
        }
    }

    private async Task<AutoHttpsCheck> FetchOwnTokenAsync(
        string name,
        string token,
        string expected,
        CancellationToken cancellationToken)
    {
        string check = "challenge-path:" + name;
        var url = new Uri($"http://{name}/.well-known/acme-challenge/{token}");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(SelfCheckTimeout);

        try
        {
            using HttpClient client = _httpClientFactory.CreateClient();
            using HttpResponseMessage response = await client.GetAsync(url, timeout.Token);
            string body = await response.Content.ReadAsStringAsync(timeout.Token);

            if (response.IsSuccessStatusCode && string.Equals(body, expected, StringComparison.Ordinal))
            {
                return new AutoHttpsCheck(
                    check,
                    AutoHttpsCheckOutcome.Passed,
                    "the challenge path reached this application from here. That does not prove the authority can " +
                    "reach it: since 2025 it validates from several network perspectives at least 500km apart");
            }

            return new AutoHttpsCheck(
                check,
                AutoHttpsCheckOutcome.Failed,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"something answered {(int)response.StatusCode} on port 80 but not with the challenge response"),
                "a proxy, ingress controller, CDN or static file handler in front of the application is answering " +
                "/.well-known/acme-challenge. Let that path through to this process");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return new AutoHttpsCheck(
                check,
                AutoHttpsCheckOutcome.Failed,
                $"nothing answered on port 80 for '{name}': {ex.Message}",
                "an http-01 validation always starts on port 80. It has to be reachable from the public internet " +
                "and forwarded to this process, and since 2025 from several network perspectives, so a country " +
                "block, IP allowlist or CDN geo rule fails it");
        }
    }

    private static AcmeDirectory? TryParseDirectory(string body)
    {
        try
        {
            AcmeDirectory? directory = JsonSerializer.Deserialize(body, AcmeJsonContext.Default.AcmeDirectory);
            return directory?.NewOrder is null ? null : directory;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
