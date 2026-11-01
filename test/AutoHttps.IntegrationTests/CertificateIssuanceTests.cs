using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AutoHttps.Certificates;
using AutoHttps.IntegrationTests.TestCa;
using Xunit;

namespace AutoHttps.IntegrationTests;

public class CertificateIssuanceTests
{
    private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task ObtainsACertificateAndServesItOverARealTlsHandshake()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(["app.example.com"], certificate.SubjectNames.ToArray());
        Assert.True(certificate.Leaf.HasPrivateKey);
        Assert.Contains("AutoHttps Test Intermediate", certificate.Leaf.Issuer, StringComparison.Ordinal);

        TlsHandshakeResult handshake = await app.HandshakeAsync(
            "app.example.com", authority.RootCertificate, knownIntermediate: authority.IntermediateCertificate);

        Assert.Equal(certificate.Leaf.Thumbprint, handshake.Leaf.Thumbprint);
        Assert.True(handshake.ChainIsTrusted, DescribeChain(handshake));
    }

    [Fact]
    public async Task CoversEveryConfiguredDomainWithASingleCertificate()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.DomainNames.Add("www.example.com");
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(["app.example.com", "www.example.com"], certificate.SubjectNames.OrderBy(n => n, StringComparer.Ordinal).ToArray());
        Assert.Equal(1, authority.OrderCount);

        TlsHandshakeResult handshake = await app.HandshakeAsync(
            "www.example.com", authority.RootCertificate, knownIntermediate: authority.IntermediateCertificate);
        Assert.True(handshake.ChainIsTrusted, DescribeChain(handshake));
    }

    [Fact]
    public async Task TheListenOptionsIntegrationPresentsTheIssuingIntermediate()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            KestrelIntegration.ListenOptions);

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        TlsHandshakeResult handshake = await app.HandshakeAsync("app.example.com", authority.RootCertificate);

        // The client trusts only the test root, so the chain can only be completed if the server
        // actually transmitted the intermediate during the handshake.
        Assert.True(handshake.ChainIsTrusted, DescribeChain(handshake));
        Assert.Contains(handshake.PresentedChain, c => c.Subject.Contains("Intermediate", StringComparison.Ordinal));
    }

    [Fact]
    public async Task HttpTwoIsStillNegotiatedOnAnAutoHttpsEndpoint()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            KestrelIntegration.ListenOptions);

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        TlsHandshakeResult handshake = await app.HandshakeAsync(
            "app.example.com",
            authority.RootCertificate,
            [System.Net.Security.SslApplicationProtocol.Http2, System.Net.Security.SslApplicationProtocol.Http11]);

        Assert.Equal(System.Net.Security.SslApplicationProtocol.Http2, handshake.NegotiatedProtocol);
    }

    [Fact]
    public async Task AnswersTheHttp01ChallengeAheadOfTheApplicationPipeline()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(
            authority,
            options =>
            {
                options.DomainNames.Add("app.example.com");
                options.StorageDirectory = storage.Path;
            },
            enableHttpsRedirection: true);

        // Without the challenge responder running first, UseHttpsRedirection would answer the
        // authority with a 307 and validation would never succeed.
        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        (HttpStatusCode status, _) = await app.GetAsync("/.well-known/acme-challenge/not-a-real-token");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, status);
    }

    [Fact]
    public async Task ServesASelfSignedFallbackWhileIssuanceKeepsFailing()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.FailValidation = true;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        TlsHandshakeResult handshake = await app.HandshakeAsync("app.example.com");

        Assert.Equal(handshake.Leaf.Subject, handshake.Leaf.Issuer);
        Assert.Null(app.FindCertificate("app.example.com"));
    }

    [Fact]
    public async Task ARequestForAnUnconfiguredNameIsRefusedRatherThanServedAWrongCertificate()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        await Assert.ThrowsAnyAsync<Exception>(() => app.HandshakeAsync("somewhere.else.test"));
    }

    [Fact]
    public async Task IssuesAWildcardCertificateThroughTheDnsChallenge()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        var dns = new RecordingDnsProvider(authority);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("*.example.com");
            options.DomainNames.Add("example.com");
            options.DnsChallengeProvider = dns;
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("anything.example.com", IssuanceTimeout);

        Assert.Contains("*.example.com", certificate.SubjectNames);
        Assert.True(certificate.Matches("api.example.com"));
        Assert.True(certificate.Matches("example.com"));

        TlsHandshakeResult handshake = await app.HandshakeAsync(
            "api.example.com", authority.RootCertificate, knownIntermediate: authority.IntermediateCertificate);
        Assert.True(handshake.ChainIsTrusted, DescribeChain(handshake));

        // Only the wildcard authorization needs DNS; the apex is validated over HTTP because that is
        // the preferred challenge type. Both records are withdrawn once validation finishes.
        Assert.Equal(1, dns.Created);
        Assert.Equal(0, authority.Dns.CountFor("_acme-challenge.example.com"));
    }

    [Fact]
    public async Task WithdrawsEachDnsRecordBeforePublishingTheNext()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        var dns = new RecordingDnsProvider(authority);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("*.example.com");
            options.DomainNames.Add("example.com");
            options.PreferredChallengeType = "dns-01";
            options.DnsChallengeProvider = dns;
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("api.example.com", IssuanceTimeout);

        // A certificate covering both an apex and its wildcard produces two authorizations whose
        // challenge records share the name _acme-challenge.example.com. Authorizations are settled
        // one at a time and each record is withdrawn before the next is published, so a provider
        // that can only hold a single value per name still works.
        Assert.Equal(2, dns.Created);
        Assert.Equal(1, dns.MaxConcurrentRecordsAtOneName);
        Assert.Equal(0, authority.Dns.CountFor("_acme-challenge.example.com"));
    }

    [Fact]
    public async Task SendsTheRequestedCertificateProfile()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.Profile = CertificateProfiles.ShortLived;
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(CertificateProfiles.ShortLived, authority.IssuedCertificates.Single().Profile);

        TimeSpan lifetime = certificate.NotAfter - certificate.NotBefore;
        Assert.InRange(lifetime.TotalHours, 159, 161);
    }

    [Fact]
    public async Task ReportsAProfileTheAuthorityDoesNotAdvertiseWithoutOrdering()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.Profile = "not-a-real-profile";
            options.StorageDirectory = storage.Path;
        });

        // The directory advertises its profiles and this one is not among them, so AutoHttps reports the
        // failure and never sends an order for it.
        DateTimeOffset deadline = DateTimeOffset.UtcNow + IssuanceTimeout;
        while (app.Log.CountOf(110) == 0 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(50);
        }

        Assert.True(app.Log.CountOf(110) > 0, "The unknown profile was not reported:" + Environment.NewLine + app.Log.Describe());
        Assert.Null(app.FindCertificate("app.example.com"));
        Assert.Equal(0, authority.OrderAttempts);
    }

    [Fact]
    public async Task RecoversWhenTheAuthorityRejectsSeveralNonces()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.RejectNextNoncesCount = 3;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
    }

    [Fact]
    public async Task RecoversWhenTheAuthorityIsBrieflyUnavailable()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.FailNextRequestsWith503Count = 2;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
    }

    [Fact]
    public async Task WaitsAsLongAsARateLimitedAuthorityAsksBeforeRetrying()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.RateLimitNextOrdersCount = 1;
        authority.Behavior.RateLimitRetryAfter = TimeSpan.FromSeconds(4);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(2, authority.OrderAttempts);
        Assert.Equal(1, authority.OrderCount);

        // The local backoff starts at 200ms in these tests. Retrying on that schedule would ignore
        // the authority and make the rate limit worse, so Retry-After has to win.
        TimeSpan betweenAttempts = authority.OrderAttemptTimes[1] - authority.OrderAttemptTimes[0];
        Assert.True(
            betweenAttempts >= TimeSpan.FromSeconds(3.5),
            $"Expected the retry to honour Retry-After, but it came after {betweenAttempts}.");
    }

    [Fact]
    public async Task RetriesFinalizeWhenTheOrderIsNotReadyYetInsteadOfOrderingAgain()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The first finalize is answered with orderNotReady, the race RFC 8555 section 7.4 describes:
        // the authorizations are valid but the order has not flipped to ready yet.
        authority.Behavior.NotReadyNextFinalizeCount = 1;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        // The order is finalized on the retry, so the certificate is still issued from the one order
        // rather than abandoning it and paying for a second against the duplicate-order limit.
        Assert.Equal(1, authority.OrderCount);
    }

    [Fact]
    public async Task AFinalizeThatWentThroughIsNotSentAgainWhenItsResponseWasLost()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        // The finalize goes through and the certificate is issued, but the client hears orderNotReady.
        // Finalizing a valid order again is refused just the same, and treating that as a failed order
        // would issue a second certificate for the same names against the duplicate limit.
        authority.Behavior.LoseNextFinalizeResponsesCount = 1;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        ServerCertificate certificate = await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(1, authority.OrderCount);
        TestIssuedCertificate issued = Assert.Single(authority.IssuedCertificates);
        Assert.Equal(issued.Leaf.Thumbprint, certificate.Leaf.Thumbprint);
        Assert.Equal(0, app.Log.CountOf(110));
    }

    [Fact]
    public async Task PollsTheAuthorizationUntilTheAuthorityMarksItValid()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.PollsBeforeAuthorizationValid = 4;

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
    }

    [Fact]
    public async Task WaitsAsLongAsTheAuthorityAsksBetweenAuthorizationPolls()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.PollsBeforeAuthorizationValid = 1;
        authority.Behavior.AuthorizationPollRetryAfter = TimeSpan.FromSeconds(4);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        var polls = authority.AuthorizationPollTimes;
        Assert.True(polls.Count >= 2, $"Expected at least two authorization polls, saw {polls.Count}.");

        // The poll interval in these tests is 100ms. Retry-After has to override it, so the gap
        // between the pending poll and the one after it lands near the four seconds asked for.
        TimeSpan longestGap = TimeSpan.Zero;
        for (int i = 1; i < polls.Count; i++)
        {
            TimeSpan gap = polls[i] - polls[i - 1];
            if (gap > longestGap)
            {
                longestGap = gap;
            }
        }

        Assert.True(
            longestGap >= TimeSpan.FromSeconds(3.5),
            $"Expected a poll to honour Retry-After, but the longest gap was {longestGap}.");
    }

    [Fact]
    public async Task RegistersWithAnExternalAccountBindingWhenTheAuthorityRequiresOne()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        byte[] hmacKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        authority.Behavior.RequireExternalAccountBinding = true;
        authority.Behavior.ExternalAccountHmacKey = hmacKey;
        authority.Behavior.ExternalAccountKeyId = "eab-key-id";

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.ExternalAccountBinding = new ExternalAccountBinding(
                "eab-key-id",
                Convert.ToBase64String(hmacKey).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        });

        await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        Assert.Equal(1, authority.AccountCount);
    }

    [Fact]
    public async Task AStoredAccountIsFoundAgainWithoutSpendingTheExternalAccountBindingTwice()
    {
        // Google Trust Services bindings work once and expire after seven days, but the configuration
        // keeps them, because the diagnostics insist on one for an authority that requires it. Sending
        // it again on every start fails at an authority that checks it before matching the key, so a
        // stored key has to find its account without it.
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();

        byte[] hmacKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        authority.Behavior.RequireExternalAccountBinding = true;
        authority.Behavior.SingleUseExternalAccountBinding = true;
        authority.Behavior.ExternalAccountHmacKey = hmacKey;

        Action<AutoHttpsOptions> configure = options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
            options.ExternalAccountBinding = new ExternalAccountBinding(
                "eab-key-id",
                Convert.ToBase64String(hmacKey).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        };

        await using (TestApplication first = await TestApplication.StartAsync(authority, configure))
        {
            await first.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        // Nothing stored but the account key, so the next start has to order, and so needs the account.
        foreach (string certificate in Directory.GetFiles(storage.Path, "*.crt.pem"))
        {
            File.Delete(certificate);
        }

        await using TestApplication second = await TestApplication.StartAsync(authority, configure);
        await second.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.Equal(1, authority.AccountCount);
        Assert.Equal(2, authority.OrderCount);
        Assert.True(authority.AccountLookups >= 1, "The stored key was registered again instead of looked up.");
    }

    [Fact]
    public async Task AStoredKeyTheAuthorityDoesNotKnowIsRegistered()
    {
        // The other side of the lookup: a key in the store whose account the authority has no record
        // of, as after a move to a new authority endpoint, still ends up with an account.
        using var storage = new TempStorage();
        await using TestCertificateAuthority first = await TestCertificateAuthority.StartAsync();

        await using (TestApplication app = await TestApplication.StartAsync(first, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        }))
        {
            await app.WaitForCertificateAsync("app.example.com", IssuanceTimeout);
        }

        await using TestCertificateAuthority second = await TestCertificateAuthority.StartAsync();

        // A different directory URL names a different account key, so the stored one is copied across
        // to make the second authority see a key it has never registered.
        string[] keys = Directory.GetFiles(storage.Path, "*.account.pem");
        string moved = Path.Combine(storage.Path, StoreKey.ForAccount(second.DirectoryUri, "operator@example.com") + ".account.pem");
        File.Copy(Assert.Single(keys), moved);

        await using TestApplication restarted = await TestApplication.StartAsync(second, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await restarted.WaitForCertificateAsync("app.example.com", IssuanceTimeout);

        Assert.True(second.AccountLookups >= 1);
        Assert.Equal(1, second.AccountCount);
    }

    [Fact]
    public async Task DoesNotObtainACertificateWhenTheExternalAccountBindingIsMissing()
    {
        using var storage = new TempStorage();
        await using TestCertificateAuthority authority = await TestCertificateAuthority.StartAsync();
        authority.Behavior.RequireExternalAccountBinding = true;
        authority.Behavior.ExternalAccountHmacKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

        await using TestApplication app = await TestApplication.StartAsync(authority, options =>
        {
            options.DomainNames.Add("app.example.com");
            options.StorageDirectory = storage.Path;
        });

        await Task.Delay(TimeSpan.FromSeconds(3));

        Assert.Null(app.FindCertificate("app.example.com"));
        Assert.Equal(0, authority.OrderCount);
    }

    private static string DescribeChain(TlsHandshakeResult handshake) =>
        $"Presented {handshake.PresentedChain.Count} certificate(s): " +
        string.Join(", ", handshake.PresentedChain.Select(c => c.Subject)) +
        ". Chain status: " + string.Join(", ", handshake.ChainStatus.Select(s => s.StatusInformation.Trim()));

    private sealed class RecordingDnsProvider : IDnsChallengeProvider
    {
        private readonly TestCertificateAuthority _authority;
        private int _created;
        private int _maxConcurrent;

        public RecordingDnsProvider(TestCertificateAuthority authority) => _authority = authority;

        public int Created => _created;

        public int MaxConcurrentRecordsAtOneName => _maxConcurrent;

        public Task CreateTxtRecordAsync(string recordName, string recordValue, System.Threading.CancellationToken cancellationToken)
        {
            System.Threading.Interlocked.Increment(ref _created);
            _authority.Dns.Add(recordName, recordValue);
            _maxConcurrent = Math.Max(_maxConcurrent, _authority.Dns.CountFor(recordName));

            return Task.CompletedTask;
        }

        public Task DeleteTxtRecordAsync(string recordName, string recordValue, System.Threading.CancellationToken cancellationToken)
        {
            _authority.Dns.Remove(recordName, recordValue);
            return Task.CompletedTask;
        }
    }
}
