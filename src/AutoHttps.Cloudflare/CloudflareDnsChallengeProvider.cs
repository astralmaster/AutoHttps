using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace AutoHttps.Cloudflare;

/// <summary>
/// Answers ACME <c>dns-01</c> challenges by publishing TXT records through the Cloudflare API.
/// </summary>
public sealed class CloudflareDnsChallengeProvider : IDnsChallengeProvider
{
    /// <summary>The name of the <see cref="HttpClient"/> this provider resolves from the factory.</summary>
    public const string HttpClientName = "AutoHttps.Cloudflare";

    private const string ApiBase = "https://api.cloudflare.com/client/v4/";
    private const string ChallengePrefix = "_acme-challenge.";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly CloudflareDnsOptions _options;
    private readonly ConcurrentDictionary<string, string> _zoneIds = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Initializes a new instance of the <see cref="CloudflareDnsChallengeProvider"/> class.</summary>
    public CloudflareDnsChallengeProvider(IHttpClientFactory httpClientFactory, IOptions<CloudflareDnsOptions> options)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);
        ArgumentNullException.ThrowIfNull(options);

        _httpClientFactory = httpClientFactory;
        _options = options.Value;
    }

    /// <inheritdoc />
    public async Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string zoneId = await ResolveZoneIdAsync(recordName, cancellationToken);
        string payload = BuildRecordPayload(recordName, recordValue, _options.RecordTtlSeconds);

        using JsonDocument _ = await SendAsync(
            HttpMethod.Post, $"zones/{zoneId}/dns_records", payload, cancellationToken);
    }

    /// <inheritdoc />
    public async Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string zoneId = await ResolveZoneIdAsync(recordName, cancellationToken);
        string query =
            $"zones/{zoneId}/dns_records?type=TXT&name={Uri.EscapeDataString(recordName)}&content={Uri.EscapeDataString(recordValue)}";

        using JsonDocument list = await SendAsync(HttpMethod.Get, query, body: null, cancellationToken);

        // Removing a record that is not there succeeds: an empty result set just means nothing to do.
        foreach (JsonElement record in list.RootElement.GetProperty("result").EnumerateArray())
        {
            string id = record.GetProperty("id").GetString()!;
            using JsonDocument _ = await SendAsync(
                HttpMethod.Delete, $"zones/{zoneId}/dns_records/{id}", body: null, cancellationToken);
        }
    }

    private async Task<string> ResolveZoneIdAsync(string recordName, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(_options.ZoneId))
        {
            return _options.ZoneId!;
        }

        string domain = recordName.StartsWith(ChallengePrefix, StringComparison.OrdinalIgnoreCase)
            ? recordName[ChallengePrefix.Length..]
            : recordName;
        domain = domain.TrimEnd('.');

        foreach (KeyValuePair<string, string> cached in _zoneIds)
        {
            if (IsWithin(domain, cached.Key))
            {
                return cached.Value;
            }
        }

        foreach (string candidate in Suffixes(domain))
        {
            using JsonDocument document = await SendAsync(
                HttpMethod.Get, $"zones?name={Uri.EscapeDataString(candidate)}", body: null, cancellationToken);

            JsonElement result = document.RootElement.GetProperty("result");
            if (result.ValueKind == JsonValueKind.Array && result.GetArrayLength() > 0)
            {
                string id = result[0].GetProperty("id").GetString()!;
                _zoneIds[candidate] = id;
                return id;
            }
        }

        throw new InvalidOperationException(
            $"No Cloudflare zone was found for '{recordName}'. Set CloudflareDnsOptions.ZoneId, or give the " +
            "API token access to the zone so it can be discovered.");
    }

    private async Task<JsonDocument> SendAsync(HttpMethod method, string url, string? body, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.ApiToken))
        {
            throw new InvalidOperationException("CloudflareDnsOptions.ApiToken is required.");
        }

        using HttpClient client = _httpClientFactory.CreateClient(HttpClientName);
        using var request = new HttpRequestMessage(method, ApiBase + url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiToken);

        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        string responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(responseBody);
        }
        catch (JsonException)
        {
            throw new InvalidOperationException(
                $"The Cloudflare API request to '{url}' returned {(int)response.StatusCode} and a body that was not JSON.");
        }

        if (!document.RootElement.TryGetProperty("success", out JsonElement success) || !success.GetBoolean())
        {
            string errors = DescribeErrors(document);
            document.Dispose();
            throw new InvalidOperationException($"The Cloudflare API request to '{url}' failed: {errors}");
        }

        return document;
    }

    private static string DescribeErrors(JsonDocument document)
    {
        if (!document.RootElement.TryGetProperty("errors", out JsonElement errors) || errors.ValueKind != JsonValueKind.Array)
        {
            return "no error detail supplied";
        }

        var parts = new List<string>();
        foreach (JsonElement error in errors.EnumerateArray())
        {
            string message = error.TryGetProperty("message", out JsonElement m) ? m.GetString() ?? string.Empty : string.Empty;
            int code = error.TryGetProperty("code", out JsonElement c) && c.ValueKind == JsonValueKind.Number ? c.GetInt32() : 0;
            parts.Add(code == 0 ? message : $"{code} {message}");
        }

        return parts.Count == 0 ? "no error detail supplied" : string.Join("; ", parts);
    }

    private static string BuildRecordPayload(string recordName, string recordValue, int ttl)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("type", "TXT");
            writer.WriteString("name", recordName);
            writer.WriteString("content", recordValue);
            writer.WriteNumber("ttl", ttl);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static bool IsWithin(string domain, string zone) =>
        string.Equals(domain, zone, StringComparison.OrdinalIgnoreCase) ||
        domain.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The candidate zone names for a domain, longest first, down to the two-label registrable name,
    /// so <c>a.b.example.com</c> is looked up as itself, then <c>b.example.com</c>, then <c>example.com</c>.
    /// </summary>
    private static IEnumerable<string> Suffixes(string domain)
    {
        string current = domain;
        while (true)
        {
            yield return current;

            int labels = 1;
            foreach (char character in current)
            {
                if (character == '.')
                {
                    labels++;
                }
            }

            if (labels <= 2)
            {
                yield break;
            }

            current = current[(current.IndexOf('.', StringComparison.Ordinal) + 1)..];
        }
    }
}
