using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Diagnostics;

/// <summary>A record type, named for the query and numbered for filtering the answers.</summary>
internal readonly record struct DnsRecordType(string Name, int Number)
{
    public static readonly DnsRecordType A = new("A", 1);
    public static readonly DnsRecordType Aaaa = new("AAAA", 28);
    public static readonly DnsRecordType Caa = new("CAA", 257);
}

/// <summary>
/// What a resolver said. <paramref name="Status"/> is the DNS response code, which is the interesting
/// part: a validating resolver answers SERVFAIL for a name whose DNSSEC chain is broken, and that looks
/// like nothing at all from a client that only asks whether records came back.
/// </summary>
internal readonly record struct DnsLookupResult(int Status, bool AuthenticatedData, IReadOnlyList<string> Records);

/// <summary>
/// Queries a DNS-over-HTTPS resolver for the diagnostics. It uses the same JSON protocol and the same
/// named client as the propagation checker, so no new dependency or outbound path is introduced.
/// </summary>
internal sealed class DnsLookup
{
    public const int NoError = 0;
    public const int ServerFailure = 2;
    public const int NameError = 3;

    private readonly IHttpClientFactory _httpClientFactory;

    public DnsLookup(IHttpClientFactory httpClientFactory) => _httpClientFactory = httpClientFactory;

    /// <summary>
    /// Asks the resolver about a name. Returns null when the resolver itself could not be reached, which
    /// is a different thing from the resolver answering that the name is broken.
    /// </summary>
    public async Task<DnsLookupResult?> QueryAsync(
        Uri resolver,
        string name,
        DnsRecordType type,
        CancellationToken cancellationToken)
    {
        try
        {
            using HttpClient client = _httpClientFactory.CreateClient(AutoHttpsDefaults.DnsHttpClientName);
            using var request = new HttpRequestMessage(HttpMethod.Get, BuildQueryUri(resolver, name, type));
            request.Headers.Accept.ParseAdd("application/dns-json");

            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            return Parse(await response.Content.ReadAsStringAsync(cancellationToken), type);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    internal static Uri BuildQueryUri(Uri resolver, string name, DnsRecordType type)
    {
        var builder = new UriBuilder(resolver);
        string existing = builder.Query.TrimStart('?');
        string parameters = $"name={Uri.EscapeDataString(name)}&type={type.Name}";
        builder.Query = existing.Length == 0 ? parameters : existing + "&" + parameters;

        return builder.Uri;
    }

    internal static DnsLookupResult Parse(string json, DnsRecordType type)
    {
        using JsonDocument document = JsonDocument.Parse(json);

        int status = document.RootElement.TryGetProperty("Status", out JsonElement statusElement) &&
            statusElement.ValueKind == JsonValueKind.Number
            ? statusElement.GetInt32()
            : -1;

        bool authenticated = document.RootElement.TryGetProperty("AD", out JsonElement adElement) &&
            adElement.ValueKind == JsonValueKind.True;

        var records = new List<string>();
        if (document.RootElement.TryGetProperty("Answer", out JsonElement answers) &&
            answers.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement answer in answers.EnumerateArray())
            {
                // A resolver may return other types for the same name, for example a CNAME alongside the
                // address it resolves to, so the answers are filtered to the type that was asked for.
                if (answer.TryGetProperty("type", out JsonElement recordType) &&
                    recordType.ValueKind == JsonValueKind.Number &&
                    recordType.GetInt32() != type.Number)
                {
                    continue;
                }

                if (answer.TryGetProperty("data", out JsonElement data) && data.ValueKind == JsonValueKind.String)
                {
                    records.Add(data.GetString()!);
                }
            }
        }

        return new DnsLookupResult(status, authenticated, records);
    }
}
