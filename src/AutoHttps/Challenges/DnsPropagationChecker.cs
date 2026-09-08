using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AutoHttps.Challenges;

/// <summary>
/// Polls a DNS-over-HTTPS resolver until a <c>dns-01</c> TXT record carrying the expected value is
/// visible, so the authority is asked to validate only once the record is actually in place rather
/// than after a fixed guess. It is inert unless <see cref="AutoHttpsOptions.DnsPropagationResolver"/>
/// is set, and never blocks issuance: a record that never appears just times out and the order goes
/// ahead, because the authority has its own tolerance for propagation.
/// </summary>
internal sealed class DnsPropagationChecker
{
    // The TXT type in a DNS answer. A resolver returns other record types for the same name, so the
    // answers have to be filtered to this one.
    private const int TxtRecordType = 16;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly Uri? _resolver;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;
    private readonly ILogger<DnsPropagationChecker> _logger;

    public DnsPropagationChecker(
        IHttpClientFactory httpClientFactory,
        IOptions<AutoHttpsOptions> options,
        TimeProvider time,
        ILogger<DnsPropagationChecker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _resolver = options.Value.DnsPropagationResolver;
        _timeout = options.Value.DnsPropagationTimeout;
        _time = time;
        _logger = logger;
    }

    public bool IsEnabled => _resolver is not null;

    /// <summary>
    /// Waits for the record to become visible through the resolver. Returns once it is, or when the
    /// timeout is reached, whichever comes first. The return value is advisory; the caller proceeds
    /// either way.
    /// </summary>
    public async Task WaitForRecordAsync(string recordName, string expectedValue, CancellationToken cancellationToken)
    {
        if (_resolver is null)
        {
            return;
        }

        DateTimeOffset deadline = _time.GetUtcNow() + _timeout;

        while (true)
        {
            if (await IsVisibleAsync(_resolver, recordName, expectedValue, cancellationToken))
            {
                Log.DnsRecordVisible(_logger, recordName);
                return;
            }

            // Break before sleeping when there is not enough time left for another poll to be worth it.
            if (_time.GetUtcNow() + PollInterval >= deadline)
            {
                Log.DnsPropagationTimedOut(_logger, recordName, _timeout);
                return;
            }

            await Task.Delay(PollInterval, _time, cancellationToken);
        }
    }

    private async Task<bool> IsVisibleAsync(Uri resolver, string recordName, string expectedValue, CancellationToken cancellationToken)
    {
        try
        {
            using HttpClient client = _httpClientFactory.CreateClient(AutoHttpsDefaults.DnsHttpClientName);
            using var request = new HttpRequestMessage(HttpMethod.Get, BuildQueryUri(resolver, recordName));
            request.Headers.Accept.ParseAdd("application/dns-json");

            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            string body = await response.Content.ReadAsStringAsync(cancellationToken);
            return ContainsValue(body, expectedValue);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            // One failed lookup is not a failure of the order; another poll follows unless time runs out.
            Log.DnsQueryFailed(_logger, recordName, ex);
            return false;
        }
    }

    internal static Uri BuildQueryUri(Uri resolver, string recordName)
    {
        var builder = new UriBuilder(resolver);
        string existing = builder.Query.TrimStart('?');
        string parameters = $"name={Uri.EscapeDataString(recordName)}&type=TXT";
        builder.Query = existing.Length == 0 ? parameters : existing + "&" + parameters;
        return builder.Uri;
    }

    internal static bool ContainsValue(string json, string expectedValue)
    {
        using JsonDocument document = JsonDocument.Parse(json);

        if (!document.RootElement.TryGetProperty("Answer", out JsonElement answers) ||
            answers.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (JsonElement answer in answers.EnumerateArray())
        {
            if (answer.TryGetProperty("type", out JsonElement type) &&
                type.ValueKind == JsonValueKind.Number &&
                type.GetInt32() != TxtRecordType)
            {
                continue;
            }

            if (!answer.TryGetProperty("data", out JsonElement data) || data.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            // A resolver quotes the TXT string, and a long one is returned as several quoted chunks that
            // concatenate. Dropping the quotes and spaces reconstructs the value a challenge encodes.
            string value = data.GetString()!.Replace("\"", string.Empty).Replace(" ", string.Empty);
            if (string.Equals(value, expectedValue, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
