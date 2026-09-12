using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace AutoHttps.IntegrationTests.TestCa;

internal sealed class TestAccount
{
    public required string Id { get; init; }

    public required JsonElement Jwk { get; init; }

    public required string Thumbprint { get; init; }

    public List<string> Contacts { get; } = [];
}

internal sealed class TestOrder
{
    public required string Id { get; init; }

    public required string AccountId { get; init; }

    public required IReadOnlyList<TestIdentifier> Identifiers { get; init; }

    public string? Profile { get; init; }

    public string? Replaces { get; init; }

    public List<string> AuthorizationIds { get; } = [];

    public string Status { get; set; } = "pending";

    public string? CertificateId { get; set; }

    public string? ErrorType { get; set; }

    public string? ErrorDetail { get; set; }

    public DateTimeOffset Expires { get; init; }
}

internal sealed record TestIdentifier(string Type, string Value)
{
    public bool IsWildcard => Value.StartsWith("*.", StringComparison.Ordinal);

    public string BaseValue => IsWildcard ? Value[2..] : Value;
}

internal sealed class TestAuthorization
{
    public required string Id { get; init; }

    public required string OrderId { get; init; }

    public required TestIdentifier Identifier { get; init; }

    public string Status { get; set; } = "pending";

    public List<TestChallenge> Challenges { get; } = [];

    public int Polls { get; set; }

    public bool ValidationSucceeded { get; set; }

    public bool ValidationAttempted { get; set; }

    public string? ErrorType { get; set; }

    public string? ErrorDetail { get; set; }
}

internal sealed class TestChallenge
{
    public required string Id { get; init; }

    public required string AuthorizationId { get; init; }

    public required string Type { get; init; }

    public required string Token { get; init; }

    public string Status { get; set; } = "pending";
}

internal sealed class TestIssuedCertificate
{
    public required string Id { get; init; }

    public required string ChainPem { get; init; }

    /// <summary>An alternate chain for the same leaf, offered with Link rel="alternate" when set.</summary>
    public string? AlternateChainPem { get; init; }

    public required X509Certificate2 Leaf { get; init; }

    public required IReadOnlyList<string> SubjectNames { get; init; }

    public string? Profile { get; init; }

    public string? Replaces { get; init; }
}

/// <summary>
/// The TXT records the test authority will see when validating a <c>dns-01</c> challenge.
/// </summary>
internal sealed class TestDnsZone
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _records =
        new(StringComparer.OrdinalIgnoreCase);

    public void Add(string name, string value) =>
        _records.GetOrAdd(name, static _ => new ConcurrentDictionary<string, byte>(StringComparer.Ordinal))[value] = 0;

    public void Remove(string name, string value)
    {
        if (_records.TryGetValue(name, out ConcurrentDictionary<string, byte>? values))
        {
            values.TryRemove(value, out _);
        }
    }

    public bool Contains(string name, string value) =>
        _records.TryGetValue(name, out ConcurrentDictionary<string, byte>? values) && values.ContainsKey(value);

    public int CountFor(string name) =>
        _records.TryGetValue(name, out ConcurrentDictionary<string, byte>? values) ? values.Count : 0;
}

/// <summary>
/// Knobs that make the test authority misbehave, so that the client's error handling can be exercised.
/// </summary>
internal sealed class TestCaBehavior
{
    public int RejectNextNoncesCount { get; set; }

    public int FailNextRequestsWith503Count { get; set; }

    public int RateLimitNextOrdersCount { get; set; }

    public TimeSpan? RateLimitRetryAfter { get; set; }

    public bool AdvertiseRenewalInfo { get; set; } = true;

    public bool AdvertiseProfiles { get; set; } = true;

    public bool RequireExternalAccountBinding { get; set; }

    public byte[]? ExternalAccountHmacKey { get; set; }

    public string? ExternalAccountKeyId { get; set; }

    public int PollsBeforeAuthorizationValid { get; set; }

    /// <summary>The Retry-After the authority returns while an authorization it has been asked to
    /// validate is still pending, as RFC 8555 section 7.5.1 allows, to pace the client's polling.</summary>
    public TimeSpan? AuthorizationPollRetryAfter { get; set; }

    public bool FailValidation { get; set; }

    /// <summary>Registers the account and then fails the response, as a connection dropped after the
    /// authority had already committed the registration would.</summary>
    public int FailNextAccountResponsesCount { get; set; }

    /// <summary>The problem type reported for a failed validation. Authorities distinguish a name
    /// that did not resolve from one that answered with the wrong thing.</summary>
    public string ValidationErrorType { get; set; } = "urn:ietf:params:acme:error:unauthorized";

    public TimeSpan CertificateLifetime { get; set; } = TimeSpan.FromDays(90);

    public Func<X509Certificate2, (DateTimeOffset Start, DateTimeOffset End)?>? RenewalWindowFactory { get; set; }

    public bool ReuseValidAuthorizations { get; set; }

    public int RejectNextFinalizeCount { get; set; }

    /// <summary>Answers orderNotReady to this many finalize attempts before accepting one, as an
    /// authority whose order has not yet flipped to ready would.</summary>
    public int NotReadyNextFinalizeCount { get; set; }

    /// <summary>Issues certificates whose validity starts in the future, as a skewed authority clock would.</summary>
    public TimeSpan NotBeforeSkew { get; set; }

    /// <summary>Forgets every account once this many orders have been placed, as a deactivated account would look.</summary>
    public int ForgetAccountsAfterOrders { get; set; } = int.MaxValue;

    /// <summary>Replies with an HTML error page, as an intercepting proxy or captive portal would.</summary>
    public int ReturnHtmlForNextRequests { get; set; }

    /// <summary>Offers a second, cross-signed chain for each certificate with Link rel="alternate".</summary>
    public bool OfferAlternateChain { get; set; }
}
