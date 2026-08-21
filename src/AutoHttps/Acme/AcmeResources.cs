using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace AutoHttps.Acme;

internal sealed class AcmeDirectory
{
    [JsonPropertyName("newNonce")] public Uri? NewNonce { get; set; }
    [JsonPropertyName("newAccount")] public Uri? NewAccount { get; set; }
    [JsonPropertyName("newOrder")] public Uri? NewOrder { get; set; }
    [JsonPropertyName("newAuthz")] public Uri? NewAuthorization { get; set; }
    [JsonPropertyName("revokeCert")] public Uri? RevokeCertificate { get; set; }
    [JsonPropertyName("keyChange")] public Uri? KeyChange { get; set; }
    [JsonPropertyName("renewalInfo")] public Uri? RenewalInfo { get; set; }
    [JsonPropertyName("meta")] public AcmeDirectoryMeta? Meta { get; set; }
}

internal sealed class AcmeDirectoryMeta
{
    [JsonPropertyName("termsOfService")] public Uri? TermsOfService { get; set; }
    [JsonPropertyName("website")] public Uri? Website { get; set; }
    [JsonPropertyName("caaIdentities")] public IReadOnlyList<string>? CaaIdentities { get; set; }
    [JsonPropertyName("externalAccountRequired")] public bool ExternalAccountRequired { get; set; }
    [JsonPropertyName("profiles")] public IReadOnlyDictionary<string, string>? Profiles { get; set; }
}

internal sealed class AcmeAccountResource
{
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("contact")] public IReadOnlyList<string>? Contact { get; set; }
    [JsonPropertyName("orders")] public Uri? Orders { get; set; }
}

internal sealed class AcmeOrderResource
{
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("expires")] public DateTimeOffset? Expires { get; set; }
    [JsonPropertyName("identifiers")] public IReadOnlyList<AcmeIdentifier>? Identifiers { get; set; }
    [JsonPropertyName("authorizations")] public IReadOnlyList<Uri>? Authorizations { get; set; }
    [JsonPropertyName("finalize")] public Uri? Finalize { get; set; }
    [JsonPropertyName("certificate")] public Uri? Certificate { get; set; }
    [JsonPropertyName("error")] public AcmeProblem? Error { get; set; }
}

internal sealed class AcmeIdentifier
{
    [JsonPropertyName("type")] public string Type { get; set; } = AcmeIdentifierTypes.Dns;
    [JsonPropertyName("value")] public string Value { get; set; } = string.Empty;
}

internal sealed class AcmeAuthorizationResource
{
    [JsonPropertyName("identifier")] public AcmeIdentifier? Identifier { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("expires")] public DateTimeOffset? Expires { get; set; }
    [JsonPropertyName("challenges")] public IReadOnlyList<AcmeChallengeResource>? Challenges { get; set; }
    [JsonPropertyName("wildcard")] public bool Wildcard { get; set; }
}

internal sealed class AcmeChallengeResource
{
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("url")] public Uri? Url { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("token")] public string? Token { get; set; }
    [JsonPropertyName("validated")] public DateTimeOffset? Validated { get; set; }
    [JsonPropertyName("error")] public AcmeProblem? Error { get; set; }
}

internal sealed class AcmeProblem
{
    [JsonPropertyName("type")] public string? Type { get; set; }
    [JsonPropertyName("title")] public string? Title { get; set; }
    [JsonPropertyName("detail")] public string? Detail { get; set; }
    [JsonPropertyName("status")] public int? Status { get; set; }
    [JsonPropertyName("subproblems")] public IReadOnlyList<AcmeProblem>? Subproblems { get; set; }
    [JsonPropertyName("identifier")] public AcmeIdentifier? Identifier { get; set; }
}

internal sealed class AcmeRenewalInfoResource
{
    [JsonPropertyName("suggestedWindow")] public AcmeRenewalWindow? SuggestedWindow { get; set; }
    [JsonPropertyName("explanationURL")] public Uri? ExplanationUrl { get; set; }
}

internal sealed class AcmeRenewalWindow
{
    [JsonPropertyName("start")] public DateTimeOffset Start { get; set; }
    [JsonPropertyName("end")] public DateTimeOffset End { get; set; }
}

internal static class AcmeIdentifierTypes
{
    public const string Dns = "dns";
    public const string Ip = "ip";
}

internal static class AcmeStatus
{
    public const string Pending = "pending";
    public const string Ready = "ready";
    public const string Processing = "processing";
    public const string Valid = "valid";
    public const string Invalid = "invalid";
    public const string Deactivated = "deactivated";
    public const string Expired = "expired";
    public const string Revoked = "revoked";
}

internal static class AcmeErrorTypes
{
    public const string BadNonce = "urn:ietf:params:acme:error:badNonce";
    public const string RateLimited = "urn:ietf:params:acme:error:rateLimited";
    public const string AccountDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist";
    public const string BadSignatureAlgorithm = "urn:ietf:params:acme:error:badSignatureAlgorithm";
    public const string AlreadyReplaced = "urn:ietf:params:acme:error:alreadyReplaced";
    public const string UserActionRequired = "urn:ietf:params:acme:error:userActionRequired";
    public const string Dns = "urn:ietf:params:acme:error:dns";
    public const string Connection = "urn:ietf:params:acme:error:connection";
    public const string Unauthorized = "urn:ietf:params:acme:error:unauthorized";
    public const string IncorrectResponse = "urn:ietf:params:acme:error:incorrectResponse";
}
