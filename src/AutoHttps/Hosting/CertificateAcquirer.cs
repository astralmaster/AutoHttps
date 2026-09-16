using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Certificates;
using AutoHttps.Challenges;
using AutoHttps.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

internal sealed class CertificateAcquirer
{
    private readonly AcmeSession _session;
    private readonly AutoHttpsOptions _options;
    private readonly IReadOnlyList<IChallengeHandler> _handlers;
    private readonly ILogger<CertificateAcquirer> _logger;

    public CertificateAcquirer(
        AcmeSession session,
        IOptions<AutoHttpsOptions> options,
        IEnumerable<IChallengeHandler> handlers,
        ILogger<CertificateAcquirer> logger)
    {
        _session = session;
        _options = options.Value;
        _logger = logger;
        _handlers = Order(handlers, _options.PreferredChallengeType);
    }

    public async Task<CertificateMaterial> AcquireAsync(
        IReadOnlyList<string> identifiers,
        string? replacesCertificateId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await OrderAsync(identifiers, replacesCertificateId, cancellationToken);
        }
        catch (AcmeException ex) when (ex.ErrorType == AcmeErrorTypes.AccountDoesNotExist)
        {
            // Retrying with the same key identifier would fail forever. Registering again with the
            // stored account key either revives the account or establishes a new one.
            Log.AccountNoLongerRecognised(_logger, ex.Detail ?? ex.Message);
            _session.InvalidateAccount();

            return await OrderAsync(identifiers, replacesCertificateId, cancellationToken);
        }
        catch (AcmeException ex) when (replacesCertificateId is not null && ex.ErrorType == AcmeErrorTypes.AlreadyReplaced)
        {
            // The replaces field (RFC 9773) only tells the authority this is a renewal, so it can
            // waive a rate limit. The authority has already accepted an order replacing this
            // certificate and refuses a second one that names it. That happens when a previous
            // renewal reached the authority but its result never became the certificate in hand, for
            // example a restart between finalizing and persisting. Keeping the field would fail the
            // same way on every attempt and the certificate would never renew. Ordering again without
            // it still gets the certificate.
            Log.CertificateAlreadyReplaced(_logger, ex.Detail ?? ex.Message);

            return await OrderAsync(identifiers, replacesCertificateId: null, cancellationToken);
        }
    }

    private async Task<CertificateMaterial> OrderAsync(
        IReadOnlyList<string> identifiers,
        string? replacesCertificateId,
        CancellationToken cancellationToken)
    {
        AcmeClient client = await _session.GetClientAsync(requireAccount: true, cancellationToken);

        string description = string.Join(", ", identifiers);
        Log.OrderStarting(_logger, description, _options.CertificateAuthority);

        AcmeOrder order = await client.CreateOrderAsync(
            [.. identifiers.Select(CreateIdentifier)],
            _options.Profile,
            replacesCertificateId,
            cancellationToken);

        foreach (Uri authorizationUrl in order.Resource.Authorizations ?? [])
        {
            await AuthorizeAsync(client, authorizationUrl, cancellationToken);
        }

        Uri finalizeUrl = order.Resource.Finalize
            ?? throw new AcmeException("The certificate authority did not return a finalize URL for the order.");

        using var key = CertificateKey.Create(_options.KeyAlgorithm);
        byte[] signingRequest = CertificateFactory.CreateSigningRequest(identifiers, key);

        try
        {
            await client.FinalizeOrderAsync(finalizeUrl, signingRequest, cancellationToken);
        }
        catch (AcmeException ex) when (ex.ErrorType == AcmeErrorTypes.OrderNotReady)
        {
            // The authorizations are valid but the order has not flipped to ready yet (RFC 8555
            // section 7.4). Wait for readiness and finalize once more, rather than abandon the order
            // and order a fresh one against the authority's duplicate-order rate limit.
            Log.OrderNotReadyRetrying(_logger, description);
            await client.WaitForOrderReadyAsync(
                order.Location, _options.ValidationTimeout, _options.PollInterval, cancellationToken);
            await client.FinalizeOrderAsync(finalizeUrl, signingRequest, cancellationToken);
        }

        AcmeOrderResource completed = await client.WaitForOrderAsync(
            order.Location, _options.ValidationTimeout, _options.PollInterval, cancellationToken);

        Uri certificateUrl = completed.Certificate
            ?? throw new AcmeException("The certificate authority marked the order valid but returned no certificate URL.");

        string chain = await SelectChainAsync(client, certificateUrl, cancellationToken);

        return new CertificateMaterial(chain, key.ExportPem());
    }

    private async Task<string> SelectChainAsync(AcmeClient client, Uri certificateUrl, CancellationToken cancellationToken)
    {
        AcmeCertificate primary = await client.DownloadCertificateAsync(certificateUrl, cancellationToken);

        string? preferred = _options.PreferredChain;
        if (string.IsNullOrWhiteSpace(preferred) || ChainSelector.Matches(primary.Pem, preferred))
        {
            return primary.Pem;
        }

        var offered = new List<string> { ChainSelector.TopIssuer(primary.Pem) };

        foreach (Uri alternate in primary.Alternates)
        {
            AcmeCertificate candidate = await client.DownloadCertificateAsync(alternate, cancellationToken);
            if (ChainSelector.Matches(candidate.Pem, preferred))
            {
                Log.PreferredChainSelected(_logger, preferred);
                return candidate.Pem;
            }

            offered.Add(ChainSelector.TopIssuer(candidate.Pem));
        }

        // The preference could not be honoured. The default chain still verifies for clients holding
        // a current root, so serving it beats failing the order over a chain preference.
        Log.PreferredChainUnavailable(_logger, preferred, string.Join(", ", offered));
        return primary.Pem;
    }

    public async Task<RenewalWindowResult> GetRenewalWindowAsync(string certificateId, CancellationToken cancellationToken)
    {
        if (!_options.UseRenewalInformation)
        {
            return default;
        }

        AcmeClient client = await _session.GetClientAsync(requireAccount: false, cancellationToken);
        AcmeRenewalInfo info = await client.GetRenewalInfoAsync(certificateId, cancellationToken);

        Renewal.RenewalWindow? window = null;
        if (info.Resource?.SuggestedWindow is { } suggested && suggested.End > suggested.Start)
        {
            Log.RenewalWindowReceived(_logger, suggested.Start, suggested.End);
            window = new Renewal.RenewalWindow(suggested.Start, suggested.End);
        }

        return new RenewalWindowResult(window, info.RetryAfter);
    }

    private async Task AuthorizeAsync(AcmeClient client, Uri authorizationUrl, CancellationToken cancellationToken)
    {
        AcmeAuthorizationResource authorization = await client.GetAuthorizationAsync(authorizationUrl, cancellationToken);

        if (authorization.Status == AcmeStatus.Valid)
        {
            return;
        }

        string identifierType = authorization.Identifier?.Type ?? AcmeIdentifierTypes.Dns;
        string identifier = authorization.Identifier?.Value
            ?? throw new AcmeException("The certificate authority returned an authorization without an identifier.");

        (IChallengeHandler handler, AcmeChallengeResource challenge) = SelectChallenge(authorization, identifierType, identifier);

        string token = challenge.Token
            ?? throw new AcmeException($"The {challenge.Type} challenge for '{identifier}' did not include a token.");
        Uri challengeUrl = challenge.Url
            ?? throw new AcmeException($"The {challenge.Type} challenge for '{identifier}' did not include a URL.");

        var context = new ChallengeContext(
            identifierType,
            identifier,
            token,
            client.AccountKey.GetKeyAuthorization(token),
            client.AccountKey.GetDnsRecordValue(token));

        try
        {
            // Preparing is inside the try because it can fail after it has already published
            // something, and a DNS record left behind would linger in a zone the operator owns.
            await handler.PrepareAsync(context, cancellationToken);
            Log.ChallengePrepared(_logger, handler.ChallengeType, identifier);

            await client.SubmitChallengeAsync(challengeUrl, cancellationToken);
            await client.WaitForAuthorizationAsync(
                authorizationUrl, _options.ValidationTimeout, _options.PollInterval, cancellationToken);
        }
        catch (AcmeException ex)
        {
            // The authority reports only what it saw from outside. The handler often knows something
            // the authority cannot, and saying it here is the difference between a minute and an
            // afternoon of looking in the wrong place.
            if (handler.DescribeFailure(context, ex) is { } explanation)
            {
                Log.ChallengeNotDelivered(_logger, handler.ChallengeType, identifier, explanation);
            }

            throw;
        }
        finally
        {
            await CleanupAsync(handler, context);
        }
    }

    private async Task CleanupAsync(IChallengeHandler handler, ChallengeContext context)
    {
        try
        {
            await handler.CleanupAsync(context, CancellationToken.None);
            Log.ChallengeCleanedUp(_logger, handler.ChallengeType, context.Identifier);
        }
        catch (Exception ex)
        {
            Log.ChallengeCleanupFailed(_logger, handler.ChallengeType, context.Identifier, ex);
        }
    }

    private (IChallengeHandler Handler, AcmeChallengeResource Challenge) SelectChallenge(
        AcmeAuthorizationResource authorization,
        string identifierType,
        string identifier)
    {
        IReadOnlyList<AcmeChallengeResource> offered = authorization.Challenges ?? [];

        foreach (IChallengeHandler handler in _handlers)
        {
            if (!handler.CanHandle(identifierType))
            {
                continue;
            }

            foreach (AcmeChallengeResource challenge in offered)
            {
                if (string.Equals(challenge.Type, handler.ChallengeType, StringComparison.Ordinal))
                {
                    return (handler, challenge);
                }
            }
        }

        string offeredTypes = offered.Count == 0
            ? "none"
            : string.Join(", ", offered.Select(static c => c.Type));
        string configured = string.Join(", ", _handlers.Select(static h => h.ChallengeType));

        throw new AcmeException(
            $"No configured challenge handler can satisfy the authorization for '{identifier}'. " +
            $"The certificate authority offered: {offeredTypes}. AutoHttps is configured for: {configured}. " +
            "A wildcard domain requires a DnsChallengeProvider.");
    }

    private static AcmeIdentifier CreateIdentifier(string value) => new()
    {
        Type = IPAddress.TryParse(value, out _) ? AcmeIdentifierTypes.Ip : AcmeIdentifierTypes.Dns,
        Value = value,
    };

    private static IReadOnlyList<IChallengeHandler> Order(IEnumerable<IChallengeHandler> handlers, string preferred)
    {
        return [.. handlers.OrderByDescending(h => string.Equals(h.ChallengeType, preferred, StringComparison.Ordinal))];
    }
}

internal readonly record struct RenewalWindowResult(Renewal.RenewalWindow? Window, DateTimeOffset? RecheckAt);
