using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Internal;
using Microsoft.Extensions.Logging;

namespace AutoHttps.Acme;

internal sealed class AcmeHttpClient
{
    private const string JoseContentType = "application/jose+json";
    private const int MaxBadNonceRetries = 5;
    private const int MaxTransientRetries = 4;

    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromMinutes(5);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _httpClientName;
    private readonly Uri _directoryUri;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly ConcurrentStack<string> _nonces = new();

    private Task<AcmeDirectory>? _directory;

    public AcmeHttpClient(
        IHttpClientFactory httpClientFactory,
        string httpClientName,
        Uri directoryUri,
        ILogger logger,
        TimeProvider time)
    {
        _httpClientFactory = httpClientFactory;
        _httpClientName = httpClientName;
        _directoryUri = directoryUri;
        _logger = logger;
        _time = time;
    }

    // A client is taken per request rather than held for the process lifetime, so that the factory
    // can rotate the underlying handler and pick up DNS changes on a server that runs for months.
    private HttpClient CreateClient() => _httpClientFactory.CreateClient(_httpClientName);

    public Task<AcmeDirectory> GetDirectoryAsync(CancellationToken cancellationToken)
    {
        Task<AcmeDirectory>? cached = Volatile.Read(ref _directory);
        if (cached is not null && !cached.IsFaulted && !cached.IsCanceled)
        {
            return cached;
        }

        Task<AcmeDirectory> fetch = FetchDirectoryAsync(cancellationToken);
        Volatile.Write(ref _directory, fetch);
        return fetch;
    }

    private async Task<AcmeDirectory> FetchDirectoryAsync(CancellationToken cancellationToken)
    {
        AcmeResponse<AcmeDirectory> response = await SendWithRetryAsync(
            () => new HttpRequestMessage(HttpMethod.Get, _directoryUri),
            AcmeJsonContext.Default.AcmeDirectory,
            cancellationToken);

        return response.Content ?? throw new AcmeException("The ACME directory response was empty.");
    }

    public async Task<AcmeResponse<T>> PostAsync<T>(
        AcmeKey key,
        string? keyId,
        Uri url,
        string payload,
        JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        for (int attempt = 0; attempt < MaxBadNonceRetries; attempt++)
        {
            string nonce = await TakeNonceAsync(cancellationToken);
            string jws = JsonWebSignature.Encode(key, url, nonce, keyId, payload);

            try
            {
                return await SendWithRetryAsync(() => CreateJwsRequest(url, jws, accept: null), typeInfo, cancellationToken);
            }
            catch (AcmeException ex) when (ex.ErrorType == AcmeErrorTypes.BadNonce)
            {
                lastError = ex;
                Log.NonceRejected(_logger, url);
            }
        }

        throw new AcmeException(
            $"The certificate authority repeatedly rejected the replay nonce for '{url}'.",
            lastError ?? new AcmeException("badNonce"));
    }

    public Task<AcmeResponse<T>> PostAsGetAsync<T>(
        AcmeKey key,
        string keyId,
        Uri url,
        JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken) =>
        PostAsync(key, keyId, url, string.Empty, typeInfo, cancellationToken);

    public async Task<AcmeRawResponse> PostAsGetRawAsync(
        AcmeKey key,
        string keyId,
        Uri url,
        string accept,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < MaxBadNonceRetries; attempt++)
        {
            string nonce = await TakeNonceAsync(cancellationToken);
            string jws = JsonWebSignature.Encode(key, url, nonce, keyId, string.Empty);

            try
            {
                AcmeResponse<object> response = await SendWithRetryAsync<object>(
                    () => CreateJwsRequest(url, jws, accept),
                    typeInfo: null,
                    cancellationToken);

                return new AcmeRawResponse(response.RawBody, response.Links);
            }
            catch (AcmeException ex) when (ex.ErrorType == AcmeErrorTypes.BadNonce)
            {
                Log.NonceRejected(_logger, url);
            }
        }

        throw new AcmeException($"The certificate authority repeatedly rejected the replay nonce for '{url}'.");
    }

    public Task<AcmeResponse<T>> GetAsync<T>(Uri url, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken) =>
        SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Get, url), typeInfo, cancellationToken);

    private static HttpRequestMessage CreateJwsRequest(Uri url, string jws, string? accept)
    {
        var content = new StringContent(jws, Encoding.UTF8);

        // RFC 8555 section 6.2 requires exactly "application/jose+json". Certificate authorities
        // compare the header as a string, so the "; charset=utf-8" that StringContent would append
        // gets the request rejected with a 415.
        content.Headers.ContentType = new MediaTypeHeaderValue(JoseContentType);

        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };

        if (accept is not null)
        {
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(accept));
        }

        return request;
    }

    private async Task<string> TakeNonceAsync(CancellationToken cancellationToken)
    {
        if (_nonces.TryPop(out string? nonce))
        {
            return nonce;
        }

        AcmeDirectory directory = await GetDirectoryAsync(cancellationToken);
        Uri newNonce = directory.NewNonce
            ?? throw new AcmeException("The ACME directory does not advertise a newNonce endpoint.");

        using var request = new HttpRequestMessage(HttpMethod.Head, newNonce);
        using HttpClient client = CreateClient();
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        CaptureNonce(response);

        if (_nonces.TryPop(out nonce))
        {
            return nonce;
        }

        throw new AcmeException("The certificate authority did not supply a replay nonce.");
    }

    private async Task<AcmeResponse<T>> SendWithRetryAsync<T>(
        Func<HttpRequestMessage> requestFactory,
        JsonTypeInfo<T>? typeInfo,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; ; attempt++)
        {
            using HttpRequestMessage request = requestFactory();
            HttpResponseMessage response;

            try
            {
                using HttpClient client = CreateClient();
                response = await client.SendAsync(request, cancellationToken);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
            {
                if (attempt >= MaxTransientRetries)
                {
                    throw new AcmeException($"The request to '{request.RequestUri}' failed after {attempt + 1} attempts.", ex);
                }

                TimeSpan backoff = TimeSpan.FromSeconds(Math.Pow(2, attempt));
                Log.TransportRetry(_logger, backoff, ex);
                await Task.Delay(backoff, _time, cancellationToken);
                continue;
            }

            using (response)
            {
                CaptureNonce(response);
                string body = await response.Content.ReadAsStringAsync(cancellationToken);

                DateTimeOffset? retryAfter = ParseRetryAfter(response);

                if (response.IsSuccessStatusCode)
                {
                    T? content = typeInfo is null || body.Length == 0 ? default : Deserialize(body, typeInfo);
                    return new AcmeResponse<T>(response.StatusCode, content, response.Headers.Location, ParseLinks(response), body, retryAfter);
                }

                AcmeProblem? problem = TryParseProblem(body);

                if (attempt < MaxTransientRetries && ShouldRetry(response.StatusCode, problem))
                {
                    TimeSpan delay = retryAfter is { } retryAt
                        ? retryAt - _time.GetUtcNow()
                        : TimeSpan.FromSeconds(Math.Pow(2, attempt));

                    if (delay > TimeSpan.Zero && delay <= MaxRetryDelay)
                    {
                        Log.ServerErrorRetry(_logger, (int)response.StatusCode, delay);
                        await Task.Delay(delay, _time, cancellationToken);
                        continue;
                    }
                }

                throw CreateException(response.StatusCode, problem, retryAfter, request.RequestUri, body);
            }
        }
    }

    private static bool ShouldRetry(HttpStatusCode statusCode, AcmeProblem? problem)
    {
        if (problem?.Type == AcmeErrorTypes.BadNonce)
        {
            return false;
        }

        return statusCode is HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;
    }

    private static AcmeException CreateException(
        HttpStatusCode statusCode,
        AcmeProblem? problem,
        DateTimeOffset? retryAfter,
        Uri? requestUri,
        string body)
    {
        string detail = problem?.Detail ?? (body.Length <= 512 ? body : body[..512]);
        string message = string.Create(
            CultureInfo.InvariantCulture,
            $"The certificate authority rejected the request to '{requestUri}' with status {(int)statusCode}: {detail}");

        if (statusCode == HttpStatusCode.TooManyRequests || problem?.Type == AcmeErrorTypes.RateLimited)
        {
            return new AcmeRateLimitException(message, problem?.Detail, retryAfter);
        }

        return new AcmeException(message, problem?.Type, problem?.Detail, (int)statusCode);
    }

    private static T? Deserialize<T>(string body, JsonTypeInfo<T> typeInfo)
    {
        try
        {
            return JsonSerializer.Deserialize(body, typeInfo);
        }
        catch (JsonException ex)
        {
            throw new AcmeException("The certificate authority returned a response that could not be parsed.", ex);
        }
    }

    private static AcmeProblem? TryParseProblem(string body)
    {
        if (body.Length == 0)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(body, AcmeJsonContext.Default.AcmeProblem);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private void CaptureNonce(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Replay-Nonce", out IEnumerable<string>? values))
        {
            return;
        }

        foreach (string value in values)
        {
            if (!string.IsNullOrEmpty(value))
            {
                _nonces.Push(value);
            }
        }
    }

    private DateTimeOffset? ParseRetryAfter(HttpResponseMessage response)
    {
        RetryConditionHeaderValue? header = response.Headers.RetryAfter;
        if (header is null)
        {
            return null;
        }

        if (header.Date is { } date)
        {
            return date;
        }

        return header.Delta is { } delta ? _time.GetUtcNow() + delta : null;
    }

    private static IReadOnlyList<AcmeLink> ParseLinks(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Link", out IEnumerable<string>? values))
        {
            return Array.Empty<AcmeLink>();
        }

        var links = new List<AcmeLink>();
        foreach (string value in values)
        {
            foreach (string candidate in SplitLinkHeader(value))
            {
                int start = candidate.IndexOf('<', StringComparison.Ordinal);
                int end = candidate.IndexOf('>', StringComparison.Ordinal);
                if (start < 0 || end <= start)
                {
                    continue;
                }

                if (Uri.TryCreate(candidate[(start + 1)..end], UriKind.Absolute, out Uri? url))
                {
                    links.Add(new AcmeLink(url, ExtractRelation(candidate[(end + 1)..])));
                }
            }
        }

        return links;
    }

    private static IEnumerable<string> SplitLinkHeader(string value)
    {
        int depth = 0;
        int start = 0;

        for (int i = 0; i < value.Length; i++)
        {
            switch (value[i])
            {
                case '<':
                    depth++;
                    break;
                case '>':
                    depth--;
                    break;
                case ',' when depth == 0:
                    yield return value[start..i];
                    start = i + 1;
                    break;
                default:
                    break;
            }
        }

        if (start < value.Length)
        {
            yield return value[start..];
        }
    }

    private static string ExtractRelation(string parameters)
    {
        foreach (string part in parameters.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!part.StartsWith("rel", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            int equals = part.IndexOf('=', StringComparison.Ordinal);
            if (equals >= 0)
            {
                return part[(equals + 1)..].Trim().Trim('"');
            }
        }

        return string.Empty;
    }
}
