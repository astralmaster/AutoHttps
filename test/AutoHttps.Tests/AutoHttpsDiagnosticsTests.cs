using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.Challenges;
using AutoHttps.Diagnostics;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AutoHttps.Tests;

public class AutoHttpsDiagnosticsTests
{
    private static readonly Uri Authority = new("https://acme.example.com/directory");
    private static readonly Uri Resolver = new("https://dns.example.com/resolve");

    private const string DirectoryJson = """
        {
          "newNonce": "https://acme.example.com/nonce",
          "newAccount": "https://acme.example.com/account",
          "newOrder": "https://acme.example.com/order",
          "renewalInfo": "https://acme.example.com/renewal",
          "meta": { "caaIdentities": [ "letsencrypt.org" ], "profiles": { "shortlived": "6 days", "classic": "90 days" } }
        }
        """;

    // Authority

    [Fact]
    public async Task AReachableAuthorityThatOffersRenewalInformationSaysSo()
    {
        AutoHttpsCheck check = Find(await RunAsync(new Routes()), "authority");

        Assert.Equal(AutoHttpsCheckOutcome.Passed, check.Outcome);
        Assert.Contains("renewal information", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAuthorityWithoutRenewalInformationIsReportedAsSuch()
    {
        var routes = new Routes
        {
            DirectoryBody = """
                { "newOrder": "https://acme.example.com/order", "meta": { } }
                """,
        };

        Assert.Contains("does not offer renewal information", Find(await RunAsync(routes), "authority").Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAuthorityThatCannotBeReachedNamesTheHttpClientToConfigure()
    {
        var routes = new Routes { DirectoryError = new HttpRequestException("no route to host") };

        AutoHttpsCheck check = Find(await RunAsync(routes), "authority");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("no route to host", check.Detail, StringComparison.Ordinal);
        Assert.Contains("HttpClientName", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAuthorityThatAnswersAnErrorStatusFails()
    {
        var routes = new Routes { DirectoryStatus = HttpStatusCode.NotFound };

        AutoHttpsCheck check = Find(await RunAsync(routes), "authority");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("404", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SomethingThatIsNotAnAcmeDirectoryFails()
    {
        // Pointing at the authority's website rather than its directory is an easy mistake and the error
        // it produces later says nothing about the cause.
        var routes = new Routes { DirectoryBody = "<html>hello</html>" };

        AutoHttpsCheck check = Find(await RunAsync(routes), "authority");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("not an ACME directory", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ChecksThatNeedTheDirectoryAreNotInventedWhenItCouldNotBeRead()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(new Routes { DirectoryError = new HttpRequestException("down") });

        Assert.DoesNotContain(report.Checks, check => check.Name == "clock");
        Assert.DoesNotContain(report.Checks, check => check.Name == "account-binding");
    }

    // Clock

    [Fact]
    public async Task AClockCloseToTheAuthoritysPasses()
    {
        var now = new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);
        var routes = new Routes { DirectoryDate = now.AddSeconds(-3) };

        Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(await RunAsync(routes, time: new FakeTimeProvider(now)), "clock").Outcome);
    }

    [Fact]
    public async Task AClockFarFromTheAuthoritysIsReported()
    {
        var now = new DateTimeOffset(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);
        var routes = new Routes { DirectoryDate = now.AddHours(-2) };

        AutoHttpsCheck check = Find(await RunAsync(routes, time: new FakeTimeProvider(now)), "clock");

        Assert.Equal(AutoHttpsCheckOutcome.Warning, check.Outcome);
        Assert.Contains("synchronise the clock", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAuthorityThatSendsNoDateHeaderSkipsTheClockCheck() =>
        Assert.Equal(AutoHttpsCheckOutcome.Skipped, Find(await RunAsync(new Routes { DirectoryDate = null }), "clock").Outcome);

    // Account binding

    [Fact]
    public async Task AnAuthorityRequiringAccountBindingWithoutOneFails()
    {
        var routes = new Routes
        {
            DirectoryBody = """
                { "newOrder": "https://acme.example.com/order", "meta": { "externalAccountRequired": true } }
                """,
        };

        AutoHttpsCheck check = Find(await RunAsync(routes), "account-binding");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("ExternalAccountBinding", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAuthorityRequiringAccountBindingWithOnePasses()
    {
        var routes = new Routes
        {
            DirectoryBody = """
                { "newOrder": "https://acme.example.com/order", "meta": { "externalAccountRequired": true } }
                """,
        };

        AutoHttpsDiagnosticsReport report = await RunAsync(
            routes,
            configure: options => options.ExternalAccountBinding = new ExternalAccountBinding("kid", "c2VjcmV0"));

        Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(report, "account-binding").Outcome);
    }

    // Profile

    [Fact]
    public async Task AProfileTheAuthorityOffersPasses()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(
            new Routes(),
            configure: options => options.Profile = CertificateProfiles.ShortLived);

        Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(report, "profile").Outcome);
    }

    [Fact]
    public async Task AProfileTheAuthorityDoesNotOfferFailsAndListsTheOnesItDoes()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(
            new Routes(),
            configure: options => options.Profile = "not-a-real-profile");

        AutoHttpsCheck check = Find(report, "profile");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("shortlived", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AProfileRequestedFromAnAuthorityThatAdvertisesNoneIsFlaggedAsPossiblyIgnored()
    {
        var routes = new Routes
        {
            DirectoryBody = """{ "newOrder": "https://acme.example.com/order", "meta": { } }""",
        };

        AutoHttpsDiagnosticsReport report = await RunAsync(
            routes,
            configure: options => options.Profile = CertificateProfiles.ShortLived);

        AutoHttpsCheck check = Find(report, "profile");

        Assert.Equal(AutoHttpsCheckOutcome.Skipped, check.Outcome);
        Assert.Contains("may be ignored", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoProfileMeansNoProfileCheck()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(new Routes());

        Assert.DoesNotContain(report.Checks, check => check.Name == "profile");
    }

    // Configuration

    [Fact]
    public async Task MoreNamesThanTheProfileAllowsIsReportedBeforeTheAuthorityRefuses()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(new Routes(), configure: options =>
        {
            options.Profile = CertificateProfiles.ShortLived;
            for (int i = 0; i < 30; i++)
            {
                options.DomainNames.Add(string.Create(CultureInfo.InvariantCulture, $"host{i}.example.com"));
            }
        });

        AutoHttpsCheck check = Find(report, "configuration");

        Assert.Equal(AutoHttpsCheckOutcome.Warning, check.Outcome);
        Assert.Contains("25", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnIpAddressWithoutTheShortLivedProfileIsReported()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(
            new Routes(),
            configure: options => options.DomainNames.Add("203.0.113.5"));

        AutoHttpsCheck check = Find(report, "configuration");

        Assert.Equal(AutoHttpsCheckOutcome.Warning, check.Outcome);
        Assert.Contains(CertificateProfiles.ShortLived, check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnIpAddressWithDnsValidationIsReported()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(new Routes(), configure: options =>
        {
            options.DomainNames.Add("203.0.113.5");
            options.Profile = CertificateProfiles.ShortLived;
            options.PreferredChallengeType = ChallengeTypes.Dns01;
        });

        Assert.Contains("dns-01", Find(report, "configuration").Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnOrdinaryConfigurationPasses() =>
        Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(await RunAsync(new Routes()), "configuration").Outcome);

    // DNS

    [Fact]
    public async Task WithoutAResolverTheDnsChecksAreSkippedRatherThanQueryingAnyway()
    {
        // AutoHttps documents that it makes no DNS queries of its own unless a resolver is configured, and
        // the diagnostics must not quietly break that promise.
        AutoHttpsDiagnosticsReport report = await RunAsync(new Routes(), configure: options => options.DnsPropagationResolver = null);

        AutoHttpsCheck check = Find(report, "dns");

        Assert.Equal(AutoHttpsCheckOutcome.Skipped, check.Outcome);
        Assert.Contains("DnsPropagationResolver", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AResolvableNamePassesAndSaysAMissingAaaaIsNormal()
    {
        AutoHttpsCheck check = Find(await RunAsync(new Routes()), "dns:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Passed, check.Outcome);
        Assert.Contains("203.0.113.5", check.Detail, StringComparison.Ordinal);
        Assert.Contains("no AAAA record, which is normal", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AServerFailureIsExplainedAsABrokenDnssecChain()
    {
        // The failure this whole feature exists for: a validating resolver answers SERVFAIL, an ordinary
        // lookup from the same host succeeds, and the authority cannot resolve the name at all.
        var routes = new Routes
        {
            Dns = (_, type) => type == DnsRecordType.A ? (DnsLookup.ServerFailure, [], false) : (DnsLookup.NoError, [], false),
        };

        AutoHttpsCheck check = Find(await RunAsync(routes), "dns:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("SERVFAIL", check.Detail, StringComparison.Ordinal);
        Assert.Contains("DNSSEC", check.Remedy!, StringComparison.Ordinal);
        Assert.Contains("dnsviz.net", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AMissingNameFails()
    {
        var routes = new Routes { Dns = (_, _) => (DnsLookup.NameError, [], false) };

        AutoHttpsCheck check = Find(await RunAsync(routes), "dns:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("NXDOMAIN", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ANameThatResolvesWithNoAddressFails()
    {
        var routes = new Routes { Dns = (_, _) => (DnsLookup.NoError, [], false) };

        Assert.Equal(AutoHttpsCheckOutcome.Failed, Find(await RunAsync(routes), "dns:app.example.com").Outcome);
    }

    [Fact]
    public async Task AValidatedChainIsReported()
    {
        var routes = new Routes
        {
            Dns = (_, type) => type == DnsRecordType.A
                ? (DnsLookup.NoError, ["203.0.113.5"], true)
                : (DnsLookup.NoError, [], false),
        };

        Assert.Contains("DNSSEC validated", Find(await RunAsync(routes), "dns:app.example.com").Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AResolverThatCannotBeReachedIsAWarningNotAFailure()
    {
        // The resolver being down says nothing about the name, so it must not read as a broken domain.
        var routes = new Routes { DnsError = true };

        Assert.Equal(AutoHttpsCheckOutcome.Warning, Find(await RunAsync(routes), "dns:app.example.com").Outcome);
    }

    [Fact]
    public async Task AWildcardIsCheckedAtItsBaseName()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(new Routes(), configure: options =>
        {
            options.DomainNames.Clear();
            options.DomainNames.Add("*.example.com");
        });

        Assert.Contains(report.Checks, check => check.Name == "dns:example.com");
    }

    [Fact]
    public async Task AnIpIdentifierIsNotLookedUp()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(new Routes(), configure: options =>
        {
            options.DomainNames.Clear();
            options.DomainNames.Add("203.0.113.5");
            options.Profile = CertificateProfiles.ShortLived;
        });

        Assert.DoesNotContain(report.Checks, check => check.Name.StartsWith("dns:", StringComparison.Ordinal));
    }

    // CAA

    [Fact]
    public async Task NoCaaRecordsAnywhereMeansAnyAuthorityMayIssue()
    {
        AutoHttpsCheck check = Find(await RunAsync(new Routes()), "caa:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Passed, check.Outcome);
        Assert.Contains("no CAA records", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CaaRecordsNamingTheAuthorityPass()
    {
        var routes = new Routes
        {
            Dns = (name, type) => type == DnsRecordType.Caa && name == "app.example.com"
                ? (DnsLookup.NoError, ["0 issue \"letsencrypt.org\""], false)
                : DefaultDns(name, type),
        };

        Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(await RunAsync(routes), "caa:app.example.com").Outcome);
    }

    [Fact]
    public async Task CaaRecordsExcludingTheAuthorityFailWithTheRecordsAndAFix()
    {
        var routes = new Routes
        {
            Dns = (name, type) => type == DnsRecordType.Caa && name == "app.example.com"
                ? (DnsLookup.NoError, ["0 issue \"sectigo.com\""], false)
                : DefaultDns(name, type),
        };

        AutoHttpsCheck check = Find(await RunAsync(routes), "caa:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("sectigo.com", check.Detail, StringComparison.Ordinal);
        Assert.Contains("letsencrypt.org", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ThePolicyIsTakenFromTheClosestAncestorThatHasOne()
    {
        // RFC 8659 section 3: the name itself has no records, so the parent's set owns the policy.
        var routes = new Routes
        {
            Dns = (name, type) => type == DnsRecordType.Caa && name == "example.com"
                ? (DnsLookup.NoError, ["0 issue \"sectigo.com\""], false)
                : DefaultDns(name, type),
        };

        AutoHttpsCheck check = Find(await RunAsync(routes), "caa:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("example.com", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAuthorityThatPublishesNoIdentitiesSkipsTheCaaCheck()
    {
        var routes = new Routes
        {
            DirectoryBody = """{ "newOrder": "https://acme.example.com/order", "meta": { } }""",
        };

        Assert.Equal(AutoHttpsCheckOutcome.Skipped, Find(await RunAsync(routes), "caa").Outcome);
    }

    // Challenge path

    [Fact]
    public async Task TheChallengePathIsFetchedBackAndTheSeveralPerspectivesCaveatIsStated()
    {
        var store = new InMemoryHttp01ChallengeStore();
        var routes = new Routes { ServeChallengeFrom = store };

        AutoHttpsCheck check = Find(await RunAsync(routes, challenges: store), "challenge-path:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Passed, check.Outcome);
        Assert.Contains("perspectives", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SomethingElseAnsweringTheChallengePathIsNamedAsSuch()
    {
        var routes = new Routes { ChallengeResponse = _ => Text("not the token") };

        AutoHttpsCheck check = Find(await RunAsync(routes), "challenge-path:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("CDN", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NothingAnsweringOnPortEightyPointsAtPortEightyAndTheSeveralPerspectives()
    {
        AutoHttpsCheck check = Find(await RunAsync(new Routes()), "challenge-path:app.example.com");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("port 80", check.Remedy!, StringComparison.Ordinal);
        Assert.Contains("perspectives", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSyntheticTokenIsAlwaysRemovedAgain()
    {
        var store = new InMemoryHttp01ChallengeStore();

        await RunAsync(new Routes { ServeChallengeFrom = store }, challenges: store);

        Assert.Equal(0, store.Count);
    }

    [Fact]
    public async Task AChallengeStoreThatCannotBeWrittenIsReported()
    {
        AutoHttpsCheck check = Find(
            await RunAsync(new Routes(), challenges: new UnwritableStore()),
            "challenge-path");

        Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
        Assert.Contains("challenge store", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DnsValidationSkipsTheChallengePathCheck()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(
            new Routes(),
            configure: options => options.PreferredChallengeType = ChallengeTypes.Dns01);

        Assert.Equal(AutoHttpsCheckOutcome.Skipped, Find(report, "challenge-path").Outcome);
    }

    [Fact]
    public async Task AWildcardOnlyConfigurationHasNoNameToFetch()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(new Routes(), configure: options =>
        {
            options.DomainNames.Clear();
            options.DomainNames.Add("*.example.com");
        });

        Assert.Equal(AutoHttpsCheckOutcome.Skipped, Find(report, "challenge-path").Outcome);
    }

    // Port 80

    [Fact]
    public async Task BeingBoundToPortEightyPasses() =>
        Assert.Equal(
            AutoHttpsCheckOutcome.Passed,
            Find(await RunAsync(new Routes(), server: new FakeServer("http://0.0.0.0:80")), "port-80").Outcome);

    [Fact]
    public async Task NotBeingBoundToPortEightyWarnsAndMentionsTheContainerDefault()
    {
        AutoHttpsCheck check = Find(await RunAsync(new Routes(), server: new FakeServer("http://0.0.0.0:8080")), "port-80");

        Assert.Equal(AutoHttpsCheckOutcome.Warning, check.Outcome);
        Assert.Contains("8080", check.Remedy!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutAServerThePortCheckIsSkipped() =>
        Assert.Equal(AutoHttpsCheckOutcome.Skipped, Find(await RunAsync(new Routes()), "port-80").Outcome);

    [Fact]
    public async Task DnsValidationSkipsThePortCheck()
    {
        AutoHttpsDiagnosticsReport report = await RunAsync(
            new Routes(),
            server: new FakeServer("http://0.0.0.0:8080"),
            configure: options => options.PreferredChallengeType = ChallengeTypes.Dns01);

        Assert.Equal(AutoHttpsCheckOutcome.Skipped, Find(report, "port-80").Outcome);
    }

    // Storage

    [Fact]
    public async Task AWritableStorageDirectoryPasses()
    {
        string directory = Path.Combine(Path.GetTempPath(), "autohttps-diag-" + Guid.NewGuid().ToString("n"));

        try
        {
            AutoHttpsDiagnosticsReport report = await RunAsync(
                new Routes(),
                certificates: new FileSystemStore(directory),
                configure: options => options.StorageDirectory = directory);

            Assert.Equal(AutoHttpsCheckOutcome.Passed, Find(report, "storage").Outcome);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task AStorageDirectoryThatCannotBeCreatedFails()
    {
        // A file where the directory should be cannot become a directory on any platform.
        string file = Path.Combine(Path.GetTempPath(), "autohttps-diag-" + Guid.NewGuid().ToString("n"));
        await File.WriteAllTextAsync(file, string.Empty);

        try
        {
            string directory = Path.Combine(file, "certificates");
            AutoHttpsDiagnosticsReport report = await RunAsync(
                new Routes(),
                certificates: new FileSystemStore(directory),
                configure: options => options.StorageDirectory = directory);

            AutoHttpsCheck check = Find(report, "storage");

            Assert.Equal(AutoHttpsCheckOutcome.Failed, check.Outcome);
            Assert.Contains("duplicate-certificate", check.Remedy!, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task ACustomCertificateStoreIsNotProbed()
    {
        AutoHttpsCheck check = Find(await RunAsync(new Routes()), "storage");

        Assert.Equal(AutoHttpsCheckOutcome.Skipped, check.Outcome);
        Assert.Contains("InMemoryStore", check.Detail, StringComparison.Ordinal);
    }

    // Harness

    private static AutoHttpsCheck Find(AutoHttpsDiagnosticsReport report, string name) =>
        report.Checks.FirstOrDefault(check => check.Name == name)
        ?? throw new InvalidOperationException($"no '{name}' check in:{Environment.NewLine}{report}");

    private static Task<AutoHttpsDiagnosticsReport> RunAsync(
        Routes routes,
        Action<AutoHttpsOptions>? configure = null,
        IHttp01ChallengeStore? challenges = null,
        ICertificateStore? certificates = null,
        IServer? server = null,
        TimeProvider? time = null)
    {
        var options = new AutoHttpsOptions
        {
            EmailAddress = "operator@example.com",
            AcceptTermsOfService = true,
            CertificateAuthority = Authority,
            DnsPropagationResolver = Resolver,
        };

        options.DomainNames.Add("app.example.com");
        configure?.Invoke(options);

        var factory = new RoutingFactory(routes);
        var diagnostics = new Diagnostics.AutoHttpsDiagnostics(
            Options.Create(options),
            factory,
            new DnsLookup(factory),
            challenges ?? new InMemoryHttp01ChallengeStore(),
            certificates ?? new InMemoryStore(),
            server is null ? [] : [server],
            time ?? TimeProvider.System);

        return diagnostics.RunAsync(CancellationToken.None);
    }

    private static (int Status, string[] Records, bool Ad) DefaultDns(string name, DnsRecordType type) =>
        type == DnsRecordType.A ? (DnsLookup.NoError, ["203.0.113.5"], false) : (DnsLookup.NoError, [], false);

    private static HttpResponseMessage Text(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.ASCII) };

    /// <summary>
    /// What the stubbed network answers. Everything is routed on the request URI, which is enough to tell
    /// the directory fetch, the resolver queries and the self-check apart.
    /// </summary>
    private sealed class Routes
    {
        public string DirectoryBody { get; init; } = DirectoryJson;

        public HttpStatusCode DirectoryStatus { get; init; } = HttpStatusCode.OK;

        public DateTimeOffset? DirectoryDate { get; init; } = DateTimeOffset.UtcNow;

        public Exception? DirectoryError { get; init; }

        public Func<string, DnsRecordType, (int Status, string[] Records, bool Ad)>? Dns { get; init; }

        public bool DnsError { get; init; }

        /// <summary>Answers the self-check the way the middleware would, from a real store.</summary>
        public InMemoryHttp01ChallengeStore? ServeChallengeFrom { get; init; }

        public Func<string, HttpResponseMessage>? ChallengeResponse { get; init; }

        public HttpResponseMessage Respond(HttpRequestMessage request)
        {
            Uri url = request.RequestUri!;

            if (url == Authority)
            {
                if (DirectoryError is not null)
                {
                    throw DirectoryError;
                }

                var response = new HttpResponseMessage(DirectoryStatus)
                {
                    Content = new StringContent(DirectoryBody, Encoding.UTF8, "application/json"),
                };

                response.Headers.Date = DirectoryDate;
                return response;
            }

            if (url.Host == Resolver.Host)
            {
                if (DnsError)
                {
                    throw new HttpRequestException("the resolver is unreachable");
                }

                return Text(BuildDnsAnswer(url), HttpStatusCode.OK);
            }

            if (url.AbsolutePath.StartsWith("/.well-known/acme-challenge/", StringComparison.Ordinal))
            {
                string token = url.AbsolutePath["/.well-known/acme-challenge/".Length..];

                if (ChallengeResponse is not null)
                {
                    return ChallengeResponse(token);
                }

                if (ServeChallengeFrom is null)
                {
                    throw new HttpRequestException("nothing is listening on port 80");
                }

                string? answer = ServeChallengeFrom.GetAsync(token, CancellationToken.None).GetAwaiter().GetResult();
                return answer is null ? Text("not found", HttpStatusCode.NotFound) : Text(answer);
            }

            return Text("no route", HttpStatusCode.NotFound);
        }

        private string BuildDnsAnswer(Uri url)
        {
            Dictionary<string, string> query = url.Query.TrimStart('?')
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(static pair => pair.Split('=', 2))
                .ToDictionary(static pair => pair[0], static pair => Uri.UnescapeDataString(pair[1]), StringComparer.Ordinal);

            string name = query["name"];
            DnsRecordType type = query["type"] switch
            {
                "A" => DnsRecordType.A,
                "AAAA" => DnsRecordType.Aaaa,
                _ => DnsRecordType.Caa,
            };

            (int status, string[] records, bool ad) = (Dns ?? DefaultDns)(name, type);

            var answers = new StringBuilder();
            for (int i = 0; i < records.Length; i++)
            {
                answers.Append(i == 0 ? string.Empty : ",")
                    .Append(string.Create(
                        CultureInfo.InvariantCulture,
                        $"{{\"type\":{type.Number},\"data\":\"{records[i].Replace("\"", "\\\"", StringComparison.Ordinal)}\"}}"));
            }

            return string.Create(
                CultureInfo.InvariantCulture,
                $"{{\"Status\":{status},\"AD\":{(ad ? "true" : "false")},\"Answer\":[{answers}]}}");
        }
    }

    private sealed class RoutingFactory : IHttpClientFactory
    {
        private readonly Routes _routes;

        public RoutingFactory(Routes routes) => _routes = routes;

        public HttpClient CreateClient(string name) => new(new RoutingHandler(_routes), disposeHandler: true);
    }

    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly Routes _routes;

        public RoutingHandler(Routes routes) => _routes = routes;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                return Task.FromResult(_routes.Respond(request));
            }
            catch (Exception ex)
            {
                return Task.FromException<HttpResponseMessage>(ex);
            }
        }
    }

    private sealed class UnwritableStore : IHttp01ChallengeStore
    {
        public bool IsProcessLocal => false;

        public Task AddAsync(string token, string keyAuthorization, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the store is read only");

        public Task<string?> GetAsync(string token, CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task RemoveAsync(string token, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FakeServer : IServer
    {
        public FakeServer(params string[] addresses)
        {
            Features = new FeatureCollection();
            Features.Set<IServerAddressesFeature>(new Bound(addresses));
        }

        public IFeatureCollection Features { get; }

        public void Dispose()
        {
        }

        public Task StartAsync<TContext>(IHttpApplication<TContext> application, CancellationToken cancellationToken)
            where TContext : notnull => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        private sealed class Bound : IServerAddressesFeature
        {
            public Bound(string[] addresses) => Addresses = addresses;

            public ICollection<string> Addresses { get; }

            public bool PreferHostingUrls { get; set; }
        }
    }
}
