using System;
using System.Threading.Tasks;
using AutoHttps.Diagnostics;
using Xunit;

namespace AutoHttps.Tests;

public class CaaPolicyTests
{
    private static readonly string[] LetsEncrypt = ["letsencrypt.org"];
    private static readonly string[] TwoIdentities = ["letsencrypt.org", "pki.goog"];

    [Fact]
    public void RecordsNamingTheAuthorityPermitIt() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(["0 issue \"letsencrypt.org\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void RecordsNamingSomeoneElseForbidIt() =>
        Assert.Equal(
            CaaVerdict.Forbidden,
            CaaPolicy.Evaluate(["0 issue \"sectigo.com\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void AnyMatchingIdentityIsEnough() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(["0 issue \"pki.goog\""], TwoIdentities, wildcard: false));

    [Fact]
    public void RecordsWithNoIssueTagDoNotRestrictIssuance() =>
        Assert.Equal(
            CaaVerdict.NoPolicy,
            CaaPolicy.Evaluate(["0 iodef \"mailto:security@example.com\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void ASemicolonForbidsEveryAuthority() =>
        Assert.Equal(CaaVerdict.Forbidden, CaaPolicy.Evaluate(["0 issue \";\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void ParametersAfterTheDomainAreNotPartOfTheName() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(
                ["0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1\""],
                LetsEncrypt,
                wildcard: false,
                accountUri: "https://acme-v02.api.letsencrypt.org/acme/acct/1"));

    // RFC 8657. Let's Encrypt enforces both parameters today, and CA/Browser Forum ballot SC-098v2 makes
    // every public authority do so from 2027-03-15, so passing either here would point the diagnosis
    // away from the actual cause of a refused order.

    [Theory]
    [InlineData("http-01", false)]
    [InlineData("dns-01", true)]
    public void AValidationMethodsListDecidesByTheMethodInUse(string method, bool permitted) =>
        Assert.Equal(
            permitted ? CaaVerdict.Permitted : CaaVerdict.ForbiddenMethod,
            CaaPolicy.Evaluate(["0 issue \"letsencrypt.org; validationmethods=dns-01,tls-alpn-01\""], LetsEncrypt, wildcard: false, method));

    [Fact]
    public void AnAccountUriForAnotherAccountForbidsIt() =>
        Assert.Equal(
            CaaVerdict.ForbiddenAccount,
            CaaPolicy.Evaluate(
                ["0 issue \"letsencrypt.org; accounturi=https://acme.example/acct/1\""],
                LetsEncrypt,
                wildcard: false,
                accountUri: "https://acme.example/acct/2"));

    [Fact]
    public void AnAccountUriThatCannotBeComparedYetIsReportedAsUnverified() =>
        Assert.Equal(
            CaaVerdict.UnverifiedAccount,
            CaaPolicy.Evaluate(["0 issue \"letsencrypt.org; accounturi=https://acme.example/acct/1\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void ARecordWithoutParametersPermitsAlongsideOnePinnedToAnotherAccount() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(
                ["0 issue \"letsencrypt.org; accounturi=https://acme.example/acct/1\"", "0 issue \"letsencrypt.org\""],
                LetsEncrypt,
                wildcard: false,
                accountUri: "https://acme.example/acct/2"));

    [Fact]
    public void AnUnknownPropertyMarkedCriticalRefusesWhateverElseIsThere() =>
        Assert.Equal(
            CaaVerdict.UnknownCritical,
            CaaPolicy.Evaluate(["128 tbs \"unknown\"", "0 issue \"letsencrypt.org\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void AKnownPropertyMarkedCriticalIsFine() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(["128 iodef \"mailto:a@b\"", "0 issue \"letsencrypt.org\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void TheDomainIsMatchedWithoutRegardToCase() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(["0 issue \"LetsEncrypt.ORG\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void TheCriticalFlagIsStillParsed() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(["128 issue \"letsencrypt.org\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void ForAWildcardIssueWildReplacesIssue()
    {
        // RFC 8659 section 4.3: issuewild is not additive. Where it exists, issue is not consulted for a
        // wildcard, so an issue record naming this authority does not rescue it.
        string[] records = ["0 issue \"letsencrypt.org\"", "0 issuewild \"sectigo.com\""];

        Assert.Equal(CaaVerdict.Forbidden, CaaPolicy.Evaluate(records, LetsEncrypt, wildcard: true));
        Assert.Equal(CaaVerdict.Permitted, CaaPolicy.Evaluate(records, LetsEncrypt, wildcard: false));
    }

    [Fact]
    public void AWildcardFallsBackToIssueWhenThereIsNoIssueWild() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(["0 issue \"letsencrypt.org\""], LetsEncrypt, wildcard: true));

    [Fact]
    public void IssueWildIsIgnoredForANameThatIsNotAWildcard() =>
        Assert.Equal(
            CaaVerdict.NoPolicy,
            CaaPolicy.Evaluate(["0 issuewild \"sectigo.com\""], LetsEncrypt, wildcard: false));

    [Fact]
    public void MalformedRecordsAreSkippedRatherThanTakenAsAPolicy() =>
        Assert.Equal(CaaVerdict.NoPolicy, CaaPolicy.Evaluate(["nonsense", string.Empty], LetsEncrypt, wildcard: false));

    [Fact]
    public void OneMatchingRecordAmongSeveralPermits() =>
        Assert.Equal(
            CaaVerdict.Permitted,
            CaaPolicy.Evaluate(
                ["0 issue \"sectigo.com\"", "0 issue \"letsencrypt.org\""],
                LetsEncrypt,
                wildcard: false));

    [Theory]
    [InlineData("0 issue \"letsencrypt.org\"", "issue", "letsencrypt.org")]
    [InlineData("128 issuewild \"pki.goog\"", "issuewild", "pki.goog")]
    [InlineData("0 iodef \"mailto:a@b\"", "iodef", "mailto:a@b")]
    public void ARecordSplitsIntoItsTagAndValue(string record, string expectedTag, string expectedValue)
    {
        Assert.True(CaaPolicy.TryParse(record, out string tag, out string value));
        Assert.Equal(expectedTag, tag);
        Assert.Equal(expectedValue, value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("0 issue")]
    public void ARecordMissingItsPartsIsRejected(string record) =>
        Assert.False(CaaPolicy.TryParse(record, out _, out _));
}

public class ProfileLimitsTests
{
    [Theory]
    [InlineData("classic", 100)]
    [InlineData("tlsserver", 25)]
    [InlineData("shortlived", 25)]
    public void TheDocumentedLimitIsKnownForEachProfile(string profile, int expected) =>
        Assert.Equal(expected, ProfileLimits.MaxIdentifiers(profile));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("minimal")]
    public void AnUnrecognisedProfileHasNoKnownLimit(string? profile) =>
        Assert.Null(ProfileLimits.MaxIdentifiers(profile));

    [Fact]
    public void OnlyTheShortLivedProfileCarriesAnIpAddress()
    {
        Assert.True(ProfileLimits.AllowsIpIdentifiers("shortlived"));
        Assert.False(ProfileLimits.AllowsIpIdentifiers("classic"));
        Assert.False(ProfileLimits.AllowsIpIdentifiers("tlsserver"));
        Assert.False(ProfileLimits.AllowsIpIdentifiers(null));
    }
}

public class DnsLookupParsingTests
{
    [Fact]
    public void TheQueryCarriesTheNameAndType() =>
        Assert.Equal(
            "https://dns.example.com/resolve?name=app.example.com&type=A",
            DnsLookup.BuildQueryUri(new Uri("https://dns.example.com/resolve"), "app.example.com", DnsRecordType.A).AbsoluteUri);

    [Fact]
    public void AnExistingQueryOnTheResolverIsKept() =>
        Assert.Equal(
            "https://dns.example.com/resolve?ct=application/dns-json&name=app.example.com&type=CAA",
            DnsLookup.BuildQueryUri(
                new Uri("https://dns.example.com/resolve?ct=application/dns-json"),
                "app.example.com",
                DnsRecordType.Caa).AbsoluteUri);

    [Fact]
    public void AnAnswerYieldsItsStatusAndRecords()
    {
        DnsLookupResult result = DnsLookup.Parse(
            """{ "Status": 0, "AD": true, "Answer": [ { "type": 1, "data": "203.0.113.5" } ] }""",
            DnsRecordType.A);

        Assert.Equal(DnsLookup.NoError, result.Status);
        Assert.True(result.AuthenticatedData);
        Assert.Equal(["203.0.113.5"], result.Records);
    }

    [Fact]
    public void RecordsOfAnotherTypeAreFilteredOut()
    {
        // A resolver returns the CNAME alongside the address it resolves to.
        DnsLookupResult result = DnsLookup.Parse(
            """{ "Status": 0, "Answer": [ { "type": 5, "data": "other.example.com." }, { "type": 1, "data": "203.0.113.5" } ] }""",
            DnsRecordType.A);

        Assert.Equal(["203.0.113.5"], result.Records);
    }

    [Fact]
    public void AServerFailureIsReportedAsItsStatus()
    {
        DnsLookupResult result = DnsLookup.Parse("""{ "Status": 2 }""", DnsRecordType.A);

        Assert.Equal(DnsLookup.ServerFailure, result.Status);
        Assert.Empty(result.Records);
    }

    [Fact]
    public void AMissingNameIsReportedAsItsStatus() =>
        Assert.Equal(DnsLookup.NameError, DnsLookup.Parse("""{ "Status": 3 }""", DnsRecordType.A).Status);

    [Fact]
    public void AbsentAuthenticatedDataReadsAsFalse() =>
        Assert.False(DnsLookup.Parse("""{ "Status": 0 }""", DnsRecordType.A).AuthenticatedData);

    [Fact]
    public async Task AnAnswerThatIsNotJsonReadsAsNoAnswerRatherThanThrowing()
    {
        // Throwing here lost the whole diagnostics report over one resolver that was misconfigured.
        var lookup = new DnsLookup(new HtmlFactory());

        DnsLookupResult? result = await lookup.QueryAsync(
            new Uri("https://dns.example.com"), "app.example.com", DnsRecordType.A, System.Threading.CancellationToken.None);

        Assert.Null(result);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("\"blocked\"")]
    public async Task JsonThatIsNotADnsAnswerReadsAsNoAnswerRatherThanThrowing(string body)
    {
        var lookup = new DnsLookup(new HtmlFactory(body, "application/json"));

        DnsLookupResult? result = await lookup.QueryAsync(
            new Uri("https://dns.example.com/resolve"), "app.example.com", DnsRecordType.A, System.Threading.CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public void AnAnswerEntryThatIsNotAnObjectIsSkipped()
    {
        DnsLookupResult result = DnsLookup.Parse(
            """{ "Status": 0, "Answer": [ 1, null, { "type": 1, "data": "203.0.113.5" } ] }""",
            DnsRecordType.A);

        Assert.Equal(["203.0.113.5"], result.Records);
    }

    private sealed class HtmlFactory : System.Net.Http.IHttpClientFactory
    {
        private readonly string _body;
        private readonly string _mediaType;

        public HtmlFactory(string body = "<html>not dns</html>", string mediaType = "text/html")
        {
            _body = body;
            _mediaType = mediaType;
        }

        public System.Net.Http.HttpClient CreateClient(string name) => new(new FixedHandler(_body, _mediaType));

        private sealed class FixedHandler : System.Net.Http.HttpMessageHandler
        {
            private readonly string _body;
            private readonly string _mediaType;

            public FixedHandler(string body, string mediaType)
            {
                _body = body;
                _mediaType = mediaType;
            }

            protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(
                System.Net.Http.HttpRequestMessage request,
                System.Threading.CancellationToken cancellationToken) =>
                Task.FromResult(new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new System.Net.Http.StringContent(_body, System.Text.Encoding.UTF8, _mediaType),
                });
        }
    }
}

public class DiagnosticsReportTests
{
    [Fact]
    public void TheReportTakesTheWorstOutcome()
    {
        var report = new AutoHttpsDiagnosticsReport(
        [
            new AutoHttpsCheck("a", AutoHttpsCheckOutcome.Passed, "fine"),
            new AutoHttpsCheck("b", AutoHttpsCheckOutcome.Warning, "hmm"),
            new AutoHttpsCheck("c", AutoHttpsCheckOutcome.Skipped, "not run"),
        ]);

        Assert.Equal(AutoHttpsCheckOutcome.Warning, report.Outcome);
    }

    [Fact]
    public void AFailureOutweighsAWarning()
    {
        var report = new AutoHttpsDiagnosticsReport(
        [
            new AutoHttpsCheck("a", AutoHttpsCheckOutcome.Warning, "hmm"),
            new AutoHttpsCheck("b", AutoHttpsCheckOutcome.Failed, "broken"),
        ]);

        Assert.Equal(AutoHttpsCheckOutcome.Failed, report.Outcome);
    }

    [Fact]
    public void AnAllPassingReportPasses() =>
        Assert.Equal(
            AutoHttpsCheckOutcome.Passed,
            new AutoHttpsDiagnosticsReport([new AutoHttpsCheck("a", AutoHttpsCheckOutcome.Passed, "fine")]).Outcome);

    [Fact]
    public void TheTextCarriesEveryCheckAndItsRemedy()
    {
        string text = new AutoHttpsDiagnosticsReport(
        [
            new AutoHttpsCheck("dns:app.example.com", AutoHttpsCheckOutcome.Failed, "SERVFAIL", "check dnsviz.net"),
        ]).ToString();

        Assert.Contains("Failed", text, StringComparison.Ordinal);
        Assert.Contains("dns:app.example.com", text, StringComparison.Ordinal);
        Assert.Contains("SERVFAIL", text, StringComparison.Ordinal);
        Assert.Contains("check dnsviz.net", text, StringComparison.Ordinal);
    }
}
