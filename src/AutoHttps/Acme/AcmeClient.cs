using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Internal;
using Microsoft.Extensions.Logging;

namespace AutoHttps.Acme;

internal sealed class AcmeClient
{
    private const string PemChainContentType = "application/pem-certificate-chain";

    private static readonly TimeSpan MaxPollDelay = TimeSpan.FromSeconds(30);

    private readonly AcmeHttpClient _http;
    private readonly AcmeKey _accountKey;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;

    private string? _keyId;

    public AcmeClient(AcmeHttpClient http, AcmeKey accountKey, ILogger logger, TimeProvider time)
    {
        _http = http;
        _accountKey = accountKey;
        _logger = logger;
        _time = time;
    }

    public AcmeKey AccountKey => _accountKey;

    public string KeyId => _keyId ?? throw new InvalidOperationException("The ACME account has not been registered yet.");

    public Task<AcmeDirectory> GetDirectoryAsync(CancellationToken cancellationToken) =>
        _http.GetDirectoryAsync(cancellationToken);

    public async Task<string> RegisterAccountAsync(
        IReadOnlyList<string> contacts,
        bool termsOfServiceAgreed,
        ExternalAccountBinding? externalAccountBinding,
        CancellationToken cancellationToken)
    {
        AcmeDirectory directory = await _http.GetDirectoryAsync(cancellationToken);
        Uri newAccount = directory.NewAccount
            ?? throw new AcmeException("The ACME directory does not advertise a newAccount endpoint.");

        string payload = BuildAccountPayload(_accountKey, contacts, termsOfServiceAgreed, externalAccountBinding, newAccount);

        AcmeResponse<AcmeAccountResource> response = await _http.PostAsync(
            _accountKey,
            keyId: null,
            newAccount,
            payload,
            AcmeJsonContext.Default.AcmeAccountResource,
            cancellationToken);

        Uri location = response.Location
            ?? throw new AcmeException("The certificate authority did not return an account URL.");

        _keyId = location.AbsoluteUri;
        Log.AccountRegistered(_logger, _keyId);
        return _keyId;
    }

    public async Task<AcmeOrder> CreateOrderAsync(
        IReadOnlyList<AcmeIdentifier> identifiers,
        string? profile,
        string? replaces,
        CancellationToken cancellationToken)
    {
        AcmeDirectory directory = await _http.GetDirectoryAsync(cancellationToken);
        Uri newOrder = directory.NewOrder
            ?? throw new AcmeException("The ACME directory does not advertise a newOrder endpoint.");

        string payload = BuildOrderPayload(identifiers, profile, replaces);

        AcmeResponse<AcmeOrderResource> response = await _http.PostAsync(
            _accountKey,
            KeyId,
            newOrder,
            payload,
            AcmeJsonContext.Default.AcmeOrderResource,
            cancellationToken);

        AcmeOrderResource order = response.Content
            ?? throw new AcmeException("The certificate authority returned an empty order.");
        Uri location = response.Location
            ?? throw new AcmeException("The certificate authority did not return an order URL.");

        return new AcmeOrder(location, order);
    }

    public async Task<AcmeAuthorizationResource> GetAuthorizationAsync(Uri authorizationUrl, CancellationToken cancellationToken)
    {
        AcmeResponse<AcmeAuthorizationResource> response = await _http.PostAsGetAsync(
            _accountKey, KeyId, authorizationUrl, AcmeJsonContext.Default.AcmeAuthorizationResource, cancellationToken);

        return response.Content ?? throw new AcmeException("The certificate authority returned an empty authorization.");
    }

    public async Task SubmitChallengeAsync(Uri challengeUrl, CancellationToken cancellationToken) =>
        await _http.PostAsync(
            _accountKey, KeyId, challengeUrl, "{}", AcmeJsonContext.Default.AcmeChallengeResource, cancellationToken);

    public async Task<AcmeAuthorizationResource> WaitForAuthorizationAsync(
        Uri authorizationUrl,
        TimeSpan timeout,
        TimeSpan pollInterval,
        CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = _time.GetUtcNow() + timeout;

        while (true)
        {
            AcmeResponse<AcmeAuthorizationResource> response = await _http.PostAsGetAsync(
                _accountKey, KeyId, authorizationUrl, AcmeJsonContext.Default.AcmeAuthorizationResource, cancellationToken);
            AcmeAuthorizationResource authorization = response.Content
                ?? throw new AcmeException("The certificate authority returned an empty authorization.");

            switch (authorization.Status)
            {
                case AcmeStatus.Valid:
                    return authorization;
                case AcmeStatus.Invalid:
                case AcmeStatus.Deactivated:
                case AcmeStatus.Expired:
                case AcmeStatus.Revoked:
                    AcmeProblem? error = FindChallengeError(authorization);
                    throw new AcmeException(
                        $"Validation of '{authorization.Identifier?.Value}' failed: " +
                        (error?.Detail ?? error?.Type ?? $"the authorization status is '{authorization.Status}'"),
                        error?.Type,
                        error?.Detail,
                        error?.Status);
                default:
                    break;
            }

            if (_time.GetUtcNow() >= deadline)
            {
                throw new AcmeException(
                    $"Timed out waiting for the certificate authority to validate '{authorization.Identifier?.Value}'.");
            }

            await Task.Delay(PollDelay(response.RetryAfter, pollInterval), _time, cancellationToken);
        }
    }

    public async Task<AcmeOrderResource> FinalizeOrderAsync(
        Uri finalizeUrl,
        byte[] certificateSigningRequest,
        CancellationToken cancellationToken)
    {
        string payload = BuildFinalizePayload(certificateSigningRequest);

        AcmeResponse<AcmeOrderResource> response = await _http.PostAsync(
            _accountKey, KeyId, finalizeUrl, payload, AcmeJsonContext.Default.AcmeOrderResource, cancellationToken);

        return response.Content ?? throw new AcmeException("The certificate authority returned an empty order.");
    }

    public async Task<AcmeOrderResource> WaitForOrderAsync(
        Uri orderUrl,
        TimeSpan timeout,
        TimeSpan pollInterval,
        CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = _time.GetUtcNow() + timeout;

        while (true)
        {
            AcmeResponse<AcmeOrderResource> response = await _http.PostAsGetAsync(
                _accountKey, KeyId, orderUrl, AcmeJsonContext.Default.AcmeOrderResource, cancellationToken);
            AcmeOrderResource order = response.Content
                ?? throw new AcmeException("The certificate authority returned an empty order.");

            switch (order.Status)
            {
                case AcmeStatus.Valid:
                    return order;
                case AcmeStatus.Invalid:
                    throw new AcmeException(
                        $"The certificate authority rejected the order: {order.Error?.Detail ?? "no detail supplied"}",
                        order.Error?.Type,
                        order.Error?.Detail,
                        order.Error?.Status);
                default:
                    break;
            }

            if (_time.GetUtcNow() >= deadline)
            {
                throw new AcmeException("Timed out waiting for the certificate authority to issue the certificate.");
            }

            await Task.Delay(PollDelay(response.RetryAfter, pollInterval), _time, cancellationToken);
        }
    }

    // RFC 8555 section 7.5.1: while an order or authorization is still pending, the authority may
    // return a Retry-After header saying how long to wait before asking again. Honour it, but never
    // poll faster than the configured interval, and cap a single wait at MaxPollDelay so that a large
    // value cannot hold the order open well past the validation timeout.
    private TimeSpan PollDelay(DateTimeOffset? retryAfter, TimeSpan pollInterval)
    {
        if (retryAfter is not { } at)
        {
            return pollInterval;
        }

        TimeSpan requested = at - _time.GetUtcNow();
        if (requested < pollInterval)
        {
            return pollInterval;
        }

        return requested > MaxPollDelay ? MaxPollDelay : requested;
    }

    public async Task<AcmeCertificate> DownloadCertificateAsync(Uri certificateUrl, CancellationToken cancellationToken)
    {
        AcmeRawResponse response = await _http.PostAsGetRawAsync(
            _accountKey, KeyId, certificateUrl, PemChainContentType, cancellationToken);

        // RFC 8555 section 7.4.2: the authority may advertise other chains for the same certificate
        // with Link rel="alternate". Surface them so a caller can pick a different trust anchor.
        var alternates = new List<Uri>();
        foreach (AcmeLink link in response.Links)
        {
            if (string.Equals(link.Relation, "alternate", StringComparison.OrdinalIgnoreCase))
            {
                alternates.Add(link.Url);
            }
        }

        return new AcmeCertificate(response.Body, alternates);
    }

    public async Task RevokeCertificateAsync(byte[] certificateDer, int reason, CancellationToken cancellationToken)
    {
        AcmeDirectory directory = await _http.GetDirectoryAsync(cancellationToken);
        Uri revoke = directory.RevokeCertificate
            ?? throw new AcmeException("The ACME directory does not advertise a revokeCert endpoint.");

        string payload = BuildRevokePayload(certificateDer, reason);

        await _http.PostAsync(
            _accountKey, KeyId, revoke, payload, AcmeJsonContext.Default.AcmeEmptyResource, cancellationToken);
    }

    public async Task<AcmeRenewalInfoResource?> GetRenewalInfoAsync(string certificateId, CancellationToken cancellationToken)
    {
        AcmeDirectory directory = await _http.GetDirectoryAsync(cancellationToken);
        if (directory.RenewalInfo is null)
        {
            return null;
        }

        var url = new Uri(EnsureTrailingSlash(directory.RenewalInfo) + certificateId);

        try
        {
            AcmeResponse<AcmeRenewalInfoResource> response = await _http.GetAsync(
                url, AcmeJsonContext.Default.AcmeRenewalInfoResource, cancellationToken);

            return response.Content;
        }
        catch (AcmeException ex)
        {
            Log.RenewalInfoUnavailable(_logger, certificateId, ex);
            return null;
        }
    }

    private static string EnsureTrailingSlash(Uri uri)
    {
        string value = uri.AbsoluteUri;
        return value.EndsWith('/') ? value : value + "/";
    }

    private static AcmeProblem? FindChallengeError(AcmeAuthorizationResource authorization) =>
        authorization.Challenges?.FirstOrDefault(c => c.Error is not null)?.Error;

    private static string BuildAccountPayload(
        AcmeKey accountKey,
        IReadOnlyList<string> contacts,
        bool termsOfServiceAgreed,
        ExternalAccountBinding? externalAccountBinding,
        Uri newAccountUrl)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("termsOfServiceAgreed", termsOfServiceAgreed);

            if (contacts.Count > 0)
            {
                writer.WriteStartArray("contact");
                foreach (string contact in contacts)
                {
                    writer.WriteStringValue(contact);
                }

                writer.WriteEndArray();
            }

            writer.WriteEndObject();
        }

        if (externalAccountBinding is null)
        {
            return System.Text.Encoding.UTF8.GetString(stream.ToArray());
        }

        string body = System.Text.Encoding.UTF8.GetString(stream.ToArray());
        string binding = JsonWebSignature.EncodeHmac(
            externalAccountBinding.GetHmacKey(),
            externalAccountBinding.KeyId,
            newAccountUrl,
            accountKey.Jwk);

        return body[..^1] + ",\"externalAccountBinding\":" + binding + "}";
    }

    private static string BuildOrderPayload(IReadOnlyList<AcmeIdentifier> identifiers, string? profile, string? replaces)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("identifiers");

            foreach (AcmeIdentifier identifier in identifiers)
            {
                writer.WriteStartObject();
                writer.WriteString("type", identifier.Type);
                writer.WriteString("value", identifier.Value);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();

            if (!string.IsNullOrEmpty(profile))
            {
                writer.WriteString("profile", profile);
            }

            if (!string.IsNullOrEmpty(replaces))
            {
                writer.WriteString("replaces", replaces);
            }

            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string BuildRevokePayload(byte[] certificateDer, int reason)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("certificate", Internal.Base64Url.Encode(certificateDer));
            writer.WriteNumber("reason", reason);
            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string BuildFinalizePayload(byte[] certificateSigningRequest)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("csr", Internal.Base64Url.Encode(certificateSigningRequest));
            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }
}

internal sealed record AcmeOrder(Uri Location, AcmeOrderResource Resource);

internal sealed record AcmeCertificate(string Pem, IReadOnlyList<Uri> Alternates);
