using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace AutoHttps.Route53;

/// <summary>
/// Answers ACME <c>dns-01</c> challenges by publishing TXT records in an AWS Route 53 hosted zone.
/// </summary>
public sealed class Route53DnsChallengeProvider : IDnsChallengeProvider
{
    private const string ChallengePrefix = "_acme-challenge.";

    private readonly IRoute53Client _client;
    private readonly Route53DnsOptions _options;
    private readonly ConcurrentDictionary<string, string> _zoneIds = new(StringComparer.OrdinalIgnoreCase);

    internal Route53DnsChallengeProvider(IRoute53Client client, IOptions<Route53DnsOptions> options)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(options);

        _client = client;
        _options = options.Value;
    }

    /// <inheritdoc />
    public async Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string zoneId = await ResolveZoneIdAsync(recordName, cancellationToken);

        // Route 53 stores TXT values quoted. A single value replaces the record set, which is safe
        // here because AutoHttps withdraws each challenge record before it publishes the next.
        await _client.ChangeTxtAsync(zoneId, recordName, "UPSERT", _options.RecordTtlSeconds, [Quote(recordValue)], cancellationToken);
    }

    /// <inheritdoc />
    public async Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string zoneId = await ResolveZoneIdAsync(recordName, cancellationToken);

        // A DELETE has to name the record set exactly as it stands, so the current values and TTL are
        // read first. No record means there is nothing to remove, which is a success.
        Route53TxtRecord? existing = await _client.GetTxtRecordAsync(zoneId, recordName, cancellationToken);
        if (existing is null)
        {
            return;
        }

        await _client.ChangeTxtAsync(zoneId, recordName, "DELETE", existing.Ttl, existing.Values, cancellationToken);
    }

    private async Task<string> ResolveZoneIdAsync(string recordName, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(_options.HostedZoneId))
        {
            return _options.HostedZoneId!;
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
            if (await _client.FindZoneIdAsync(candidate, cancellationToken) is { } zoneId)
            {
                _zoneIds[candidate] = zoneId;
                return zoneId;
            }
        }

        throw new InvalidOperationException(
            $"No Route 53 hosted zone was found for '{recordName}'. Set Route53DnsOptions.HostedZoneId, or " +
            "grant permission to list hosted zones so it can be discovered.");
    }

    private static string Quote(string value) => "\"" + value + "\"";

    private static bool IsWithin(string domain, string zone) =>
        string.Equals(domain, zone, StringComparison.OrdinalIgnoreCase) ||
        domain.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase);

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
