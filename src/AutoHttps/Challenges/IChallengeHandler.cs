using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;

namespace AutoHttps.Challenges;

internal interface IChallengeHandler
{
    string ChallengeType { get; }

    bool CanHandle(string identifierType);

    Task PrepareAsync(ChallengeContext context, CancellationToken cancellationToken);

    Task CleanupAsync(ChallengeContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Explains a validation failure from the handler's own point of view, or returns
    /// <see langword="null"/> when it has nothing to add. The authority only reports what it saw
    /// from the outside, which is often the opposite of where the fault lies.
    /// </summary>
    string? DescribeFailure(ChallengeContext context, AcmeException failure);
}

internal sealed record ChallengeContext(string IdentifierType, string Identifier, string Token, string KeyAuthorization, string DnsRecordValue);

internal static class ChallengeTypes
{
    public const string Http01 = "http-01";
    public const string Dns01 = "dns-01";
    public const string TlsAlpn01 = "tls-alpn-01";
}
