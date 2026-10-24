using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
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

    // AWS says a change generally reaches every name server for the zone within 60 seconds. Both
    // values follow what certbot and lego settled on for the same wait.
    internal static readonly TimeSpan SyncPollInterval = TimeSpan.FromSeconds(4);
    internal static readonly TimeSpan SyncTimeout = TimeSpan.FromMinutes(2);

    private readonly IRoute53Client _client;
    private readonly Route53DnsOptions _options;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, string> _zoneIds = new(StringComparer.OrdinalIgnoreCase);

    internal Route53DnsChallengeProvider(IRoute53Client client, IOptions<Route53DnsOptions> options, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(options);

        _client = client;
        _options = options.Value;
        _time = time ?? TimeProvider.System;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Route 53 keeps every TXT value at a name in one record set, and an UPSERT replaces the whole set.
    /// Other values can be there for good reasons: a wildcard and its apex in one order both use
    /// <c>_acme-challenge</c> at the apex, and so does another application or cert-manager ordering
    /// for the same name. So the value is added to what is there rather than written over it.
    /// </remarks>
    public async Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string zoneId = await ResolveZoneIdAsync(recordName, cancellationToken);
        string value = Quote(recordValue);

        Route53TxtRecord? existing = await _client.GetTxtRecordAsync(zoneId, recordName, cancellationToken);
        if (existing is not null && existing.Values.Contains(value, StringComparer.Ordinal))
        {
            return;
        }

        // An existing set keeps its own TTL, which belongs to whoever created it.
        IReadOnlyList<string> values = existing is null ? [value] : [.. existing.Values, value];
        long ttl = existing?.Ttl ?? _options.RecordTtlSeconds;

        string changeId = await _client.ChangeTxtAsync(zoneId, recordName, "UPSERT", ttl, values, cancellationToken);
        await WaitUntilInSyncAsync(changeId, recordName, cancellationToken);
    }

    /// <summary>
    /// Waits until Route 53 reports the change on every name server for the zone. A change it has
    /// accepted is not yet visible everywhere, and an authority that asks a name server still behind
    /// fails the validation and counts it against the account. Giving up here costs an order attempt
    /// rather than one of the authority's failed-validation allowances.
    /// </summary>
    private async Task WaitUntilInSyncAsync(string changeId, string recordName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(changeId))
        {
            return;
        }

        DateTimeOffset deadline = _time.GetUtcNow() + SyncTimeout;

        while (!await _client.IsChangeInSyncAsync(changeId, cancellationToken))
        {
            if (_time.GetUtcNow() >= deadline)
            {
                throw new InvalidOperationException(
                    $"Route 53 accepted the TXT record for '{recordName}' (change {changeId}) but had not applied it to " +
                    "every name server after two minutes, so validation was not requested.");
            }

            await Task.Delay(SyncPollInterval, _time, cancellationToken);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Only the value this provider added is taken out. The set is deleted only when that value was the
    /// last one in it, and a set that does not hold the value is left as it is.
    /// </remarks>
    public async Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string zoneId = await ResolveZoneIdAsync(recordName, cancellationToken);
        string value = Quote(recordValue);

        Route53TxtRecord? existing = await _client.GetTxtRecordAsync(zoneId, recordName, cancellationToken);
        if (existing is null || !existing.Values.Contains(value, StringComparer.Ordinal))
        {
            return;
        }

        string[] remaining = [.. existing.Values.Where(stored => !string.Equals(stored, value, StringComparison.Ordinal))];

        if (remaining.Length > 0)
        {
            await _client.ChangeTxtAsync(zoneId, recordName, "UPSERT", existing.Ttl, remaining, cancellationToken);
            return;
        }

        // A DELETE has to name the record set exactly as it stands, so it carries the values and TTL
        // that were just read.
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
