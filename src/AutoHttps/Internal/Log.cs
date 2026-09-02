using System;
using Microsoft.Extensions.Logging;

namespace AutoHttps.Internal;

internal static partial class Log
{
    [LoggerMessage(EventId = 100, Level = LogLevel.Debug, Message = "The certificate authority rejected the replay nonce; retrying {Url}.")]
    public static partial void NonceRejected(ILogger logger, Uri url);

    [LoggerMessage(EventId = 101, Level = LogLevel.Debug, Message = "Transport error contacting the certificate authority; retrying in {Delay}.")]
    public static partial void TransportRetry(ILogger logger, TimeSpan delay, Exception exception);

    [LoggerMessage(EventId = 102, Level = LogLevel.Debug, Message = "The certificate authority returned {StatusCode}; retrying in {Delay}.")]
    public static partial void ServerErrorRetry(ILogger logger, int statusCode, TimeSpan delay);

    [LoggerMessage(EventId = 103, Level = LogLevel.Debug, Message = "Registered ACME account {AccountUrl}.")]
    public static partial void AccountRegistered(ILogger logger, string accountUrl);

    [LoggerMessage(EventId = 104, Level = LogLevel.Debug, Message = "No renewal information is available for {CertificateId}.")]
    public static partial void RenewalInfoUnavailable(ILogger logger, string certificateId, Exception exception);

    [LoggerMessage(EventId = 105, Level = LogLevel.Information, Message = "Requesting a certificate for {Domains} from {Authority}.")]
    public static partial void OrderStarting(ILogger logger, string domains, Uri authority);

    [LoggerMessage(EventId = 106, Level = LogLevel.Debug, Message = "Prepared a {ChallengeType} challenge for {Identifier}.")]
    public static partial void ChallengePrepared(ILogger logger, string challengeType, string identifier);

    [LoggerMessage(EventId = 107, Level = LogLevel.Information, Message = "Issued a certificate for {Domains}, valid until {NotAfter:u}.")]
    public static partial void CertificateIssued(ILogger logger, string domains, DateTimeOffset notAfter);

    [LoggerMessage(EventId = 108, Level = LogLevel.Information, Message = "Loaded a stored certificate for {Domains}, valid until {NotAfter:u}.")]
    public static partial void CertificateLoaded(ILogger logger, string domains, DateTimeOffset notAfter);

    [LoggerMessage(EventId = 109, Level = LogLevel.Information, Message = "The certificate for {Domains} will be renewed at {RenewAt:u}.")]
    public static partial void RenewalScheduled(ILogger logger, string domains, DateTimeOffset renewAt);

    [LoggerMessage(
        EventId = 110,
        Level = LogLevel.Warning,
        Message = "Failed to obtain a certificate for {Domains}: {Reason} The next attempt is in {RetryIn}.")]
    public static partial void OrderFailed(ILogger logger, string domains, string reason, TimeSpan retryIn);

    // A failed order is expected and will be retried, so the stack trace is kept out of the warning
    // that operators alert on and offered at debug level instead.
    [LoggerMessage(EventId = 124, Level = LogLevel.Debug, Message = "The failed order for {Domains} threw.")]
    public static partial void OrderFailedDetail(ILogger logger, string domains, Exception exception);

    [LoggerMessage(
        EventId = 127,
        Level = LogLevel.Warning,
        Message = "The {ChallengeType} challenge for {Identifier} failed and {Explanation}.")]
    public static partial void ChallengeNotDelivered(ILogger logger, string challengeType, string identifier, string explanation);

    [LoggerMessage(
        EventId = 126,
        Level = LogLevel.Warning,
        Message = "Serving {Domain} without the {IntermediateCount} intermediate certificate(s) the authority issued, " +
                  "because Kestrel ignores a configured chain while a certificate selector is in use. Clients that do " +
                  "not already hold the intermediate will reject this connection. Configure the endpoint with " +
                  "listenOptions.UseAutoHttps(services) to send the full chain.")]
    public static partial void IncompleteChainServed(ILogger logger, string domain, int intermediateCount);

    [LoggerMessage(
        EventId = 125,
        Level = LogLevel.Warning,
        Message = "The certificate authority no longer recognises this account ({Detail}). Registering again with the stored account key.")]
    public static partial void AccountNoLongerRecognised(ILogger logger, string detail);

    [LoggerMessage(
        EventId = 128,
        Level = LogLevel.Information,
        Message = "The certificate authority has already replaced the certificate this renewal names ({Detail}). Ordering again without the replaces hint.")]
    public static partial void CertificateAlreadyReplaced(ILogger logger, string detail);

    [LoggerMessage(EventId = 111, Level = LogLevel.Debug, Message = "Another instance holds the certificate lock for {Domains}; waiting for it to publish.")]
    public static partial void LockUnavailable(ILogger logger, string domains);

    [LoggerMessage(EventId = 112, Level = LogLevel.Warning, Message = "Serving a self-signed fallback certificate for {Domain} because no certificate has been issued yet.")]
    public static partial void FallbackCertificateServed(ILogger logger, string domain);

    [LoggerMessage(EventId = 113, Level = LogLevel.Debug, Message = "Answered an HTTP-01 challenge for token {Token}.")]
    public static partial void Http01ChallengeAnswered(ILogger logger, string token);

    [LoggerMessage(EventId = 114, Level = LogLevel.Warning, Message = "The certificate store could not be read. Continuing without a cached certificate.")]
    public static partial void StoreReadFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 115, Level = LogLevel.Warning, Message = "The issued certificate could not be saved to the store. It is in use but will not survive a restart.")]
    public static partial void StoreWriteFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 116, Level = LogLevel.Information, Message = "AutoHttps is managing certificates for {Domains}.")]
    public static partial void ServiceStarting(ILogger logger, string domains);

    [LoggerMessage(EventId = 117, Level = LogLevel.Debug, Message = "Removed the {ChallengeType} challenge for {Identifier}.")]
    public static partial void ChallengeCleanedUp(ILogger logger, string challengeType, string identifier);

    [LoggerMessage(EventId = 118, Level = LogLevel.Warning, Message = "Failed to clean up the {ChallengeType} challenge for {Identifier}.")]
    public static partial void ChallengeCleanupFailed(ILogger logger, string challengeType, string identifier, Exception exception);

    [LoggerMessage(EventId = 119, Level = LogLevel.Debug, Message = "The certificate authority suggests renewing between {Start:u} and {End:u}.")]
    public static partial void RenewalWindowReceived(ILogger logger, DateTimeOffset start, DateTimeOffset end);

    [LoggerMessage(EventId = 120, Level = LogLevel.Information, Message = "Reloaded a certificate for {Domains} published by another instance.")]
    public static partial void CertificateAdopted(ILogger logger, string domains);

    [LoggerMessage(
        EventId = 123,
        Level = LogLevel.Warning,
        Message = "The certificate authority rate limited {Domains} and asked to be left alone until {RetryAfter:u}.")]
    public static partial void RateLimited(ILogger logger, string domains, DateTimeOffset retryAfter);

    [LoggerMessage(
        EventId = 122,
        Level = LogLevel.Error,
        Message = "Certificate management for {Domains} hit an unexpected error. Retrying in {RetryIn}. " +
                  "The application keeps running and continues to serve whatever certificate it already has.")]
    public static partial void UnexpectedFailure(ILogger logger, string domains, TimeSpan retryIn, Exception exception);

    [LoggerMessage(
        EventId = 121,
        Level = LogLevel.Warning,
        Message = "The certificate for {Domains} was issued moments ago but already qualifies for renewal. " +
                  "Holding off for {Delay} to avoid exhausting the certificate authority's rate limits. " +
                  "Check RenewalThreshold against the lifetime the authority issues.")]
    public static partial void RenewalThrottled(ILogger logger, string domains, TimeSpan delay);

    [LoggerMessage(
        EventId = 129,
        Level = LogLevel.Warning,
        Message = "A certificate listener ({Listener}) threw. The certificate is unaffected and in use.")]
    public static partial void CertificateListenerFailed(ILogger logger, string listener, Exception exception);
}
