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
    private const int MaxAttempts = 5;

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
    /// Route 53 keeps every TXT value at a name in one record set, and a write replaces the whole set.
    /// Other values can be there for good reasons: a wildcard and its apex in one order both use
    /// <c>_acme-challenge</c> at the apex, and so does another application or cert-manager ordering
    /// for the same name. So the value is added to what is there rather than written over it, and the
    /// write only lands if the set is still as it was read. Otherwise it is read again and retried.
    /// </remarks>
    public async Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string zoneId = await ResolveZoneIdAsync(recordName, cancellationToken);
        string value = Quote(recordValue);

        for (int attempt = 1; ; attempt++)
        {
            Route53TxtRecord? existing = await _client.GetTxtRecordAsync(zoneId, recordName, cancellationToken);
            if (existing is not null && existing.Values.Contains(value, StringComparer.Ordinal))
            {
                return;
            }

            // An existing set keeps its own TTL, which belongs to whoever created it.
            Route53TxtRecord replacement = existing is null
                ? new Route53TxtRecord(_options.RecordTtlSeconds, [value])
                : new Route53TxtRecord(existing.Ttl, [.. existing.Values, value]);

            Route53ChangeResult result = await _client.TryReplaceTxtAsync(zoneId, recordName, existing, replacement, cancellationToken);
            if (result.ChangeId is { } changeId)
            {
                await WaitUntilInSyncAsync(changeId, recordName, cancellationToken);
                return;
            }

            ThrowIfOutOfAttempts(attempt, recordName, result.Refusal);
        }
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

        for (int attempt = 1; ; attempt++)
        {
            Route53TxtRecord? existing = await _client.GetTxtRecordAsync(zoneId, recordName, cancellationToken);
            if (existing is null || !existing.Values.Contains(value, StringComparer.Ordinal))
            {
                return;
            }

            string[] remaining = [.. existing.Values.Where(stored => !string.Equals(stored, value, StringComparison.Ordinal))];
            Route53TxtRecord? replacement = remaining.Length > 0 ? new Route53TxtRecord(existing.Ttl, remaining) : null;

            Route53ChangeResult result = await _client.TryReplaceTxtAsync(zoneId, recordName, existing, replacement, cancellationToken);
            if (result.ChangeId is not null)
            {
                return;
            }

            ThrowIfOutOfAttempts(attempt, recordName, result.Refusal);
        }
    }

    // Each retry rereads the set, so this only gives up when something keeps changing it faster than a
    // read and a write take, or when Route 53 refuses the batch for a reason a retry cannot fix, which
    // its own message then says.
    private static void ThrowIfOutOfAttempts(int attempt, string recordName, string? refusal)
    {
        if (attempt >= MaxAttempts)
        {
            throw new InvalidOperationException(
                $"Route 53 refused {MaxAttempts} changes in a row to the TXT record set '{recordName}', which happens " +
                $"when something else keeps changing it while AutoHttps updates it, so the update was abandoned. " +
                $"Route 53 said: {refusal}");
        }
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

        // Most specific first, from the cache or the API alike. Taking any cached zone that contains the
        // name would answer dev.example.com with example.com once that was cached, even where
        // dev.example.com is a hosted zone of its own, and the record would land where no resolver looks.
        // Only zones that were found are remembered. A name that is not a zone today can become one, and
        // a zone created or made visible after a failed lookup has to be found by the next attempt.
        foreach (string candidate in Suffixes(domain))
        {
            if (_zoneIds.TryGetValue(candidate, out string? cached))
            {
                return cached;
            }

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
