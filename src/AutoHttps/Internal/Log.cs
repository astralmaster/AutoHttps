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

    [LoggerMessage(
        EventId = 130,
        Level = LogLevel.Information,
        Message = "Development environment: serving the {Source} certificate for {Domains} and not contacting an authority.")]
    public static partial void DevelopmentCertificateServed(ILogger logger, string source, string domains);

    [LoggerMessage(
        EventId = 131,
        Level = LogLevel.Warning,
        Message = "Development environment: no ASP.NET Core development certificate is installed. " +
                  "Run 'dotnet dev-certs https --trust', then restart. Serving the self-signed fallback until then.")]
    public static partial void DevelopmentCertificateMissing(ILogger logger);

    [LoggerMessage(
        EventId = 132,
        Level = LogLevel.Information,
        Message = "Serving the alternate certificate chain that leads up to {Issuer}, as PreferredChain asked.")]
    public static partial void PreferredChainSelected(ILogger logger, string issuer);

    [LoggerMessage(
        EventId = 133,
        Level = LogLevel.Warning,
        Message = "PreferredChain requested a chain up to {Preferred}, but the authority offered none matching. " +
                  "Serving the default chain, which leads up to one of: {Offered}.")]
    public static partial void PreferredChainUnavailable(ILogger logger, string preferred, string offered);

    [LoggerMessage(
        EventId = 134,
        Level = LogLevel.Warning,
        Message = "The DNS record {Record} was not visible through the resolver within {Timeout}. " +
                  "Asking the authority to validate anyway.")]
    public static partial void DnsPropagationTimedOut(ILogger logger, string record, TimeSpan timeout);

    [LoggerMessage(EventId = 135, Level = LogLevel.Debug, Message = "The DNS record {Record} is visible through the resolver.")]
    public static partial void DnsRecordVisible(ILogger logger, string record);

    [LoggerMessage(EventId = 136, Level = LogLevel.Debug, Message = "A DNS-over-HTTPS lookup for {Record} failed; retrying.")]
    public static partial void DnsQueryFailed(ILogger logger, string record, Exception exception);

    [LoggerMessage(
        EventId = 137,
        Level = LogLevel.Critical,
        Message = "No certificate for {Domains} was obtained within {Timeout} of startup and " +
                  "RequireCertificateOnStartup is set. Stopping the application.")]
    public static partial void StartupCertificateTimedOut(ILogger logger, string domains, TimeSpan timeout);

    [LoggerMessage(
        EventId = 138,
        Level = LogLevel.Information,
        Message = "Revoked the certificate {Thumbprint} at the authority ({Reason}).")]
    public static partial void CertificateRevoked(ILogger logger, string thumbprint, RevocationReason reason);

    [LoggerMessage(
        EventId = 139,
        Level = LogLevel.Debug,
        Message = "Could not read Kestrel's HTTPS defaults to check that AutoHttps installed its " +
                  "certificate selector; skipping the ordering check.")]
    public static partial void KestrelDefaultsUnverifiable(ILogger logger);

    [LoggerMessage(
        EventId = 140,
        Level = LogLevel.Warning,
        Message = "The certificate authority rate limited {Domains} and asked to wait until {RequestedUntil:u}, " +
                  "longer than the certificate can afford. Retrying by {RetryBy:u} instead so it does not expire.")]
    public static partial void RateLimitCapped(ILogger logger, string domains, DateTimeOffset requestedUntil, DateTimeOffset retryBy);

    [LoggerMessage(
        EventId = 141,
        Level = LogLevel.Debug,
        Message = "The order for {Domains} was not ready to finalize yet; waiting for it and finalizing again.")]
    public static partial void OrderNotReadyRetrying(ILogger logger, string domains);

    [LoggerMessage(
        EventId = 142,
        Level = LogLevel.Warning,
        Message = "AutoHttps is configured for {Domains} but no HTTPS endpoint used the certificate selector it " +
                  "installed, so a managed name is served with a different certificate (in Development, the ASP.NET " +
                  "Core developer certificate). An endpoint declared with UseHttps before AddAutoHttps keeps the " +
                  "HTTPS defaults from before AutoHttps was added. Call AddAutoHttps before declaring HTTPS " +
                  "endpoints, bind them with UseUrls or Kestrel:Endpoints, or set ConfigureKestrel to false and " +
                  "wire endpoints with listenOptions.UseAutoHttps.")]
    public static partial void KestrelDefaultsNotApplied(ILogger logger, string domains);

    [LoggerMessage(
        EventId = 143,
        Level = LogLevel.Warning,
        Message = "The http-01 challenge store could not be read for token {Token}, so this instance " +
                  "cannot answer the authority's validation request.")]
    public static partial void Http01ChallengeStoreUnavailable(ILogger logger, string token, Exception exception);

    [LoggerMessage(
        EventId = 144,
        Level = LogLevel.Warning,
        Message = "The order failed, so AutoHttps checked its own configuration and surroundings and found " +
                  "something to look at.{Report}")]
    public static partial void DiagnosticsFoundProblems(ILogger logger, string report);

    [LoggerMessage(
        EventId = 145,
        Level = LogLevel.Information,
        Message = "The order failed, so AutoHttps checked its own configuration and surroundings and found " +
                  "nothing wrong with them.{Report}")]
    public static partial void DiagnosticsFoundNothing(ILogger logger, string report);

    [LoggerMessage(EventId = 146, Level = LogLevel.Debug, Message = "The diagnostics could not be run.")]
    public static partial void DiagnosticsFailed(ILogger logger, Exception exception);
}
