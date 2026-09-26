using System;
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
                wildcard: false));

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
