using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace AutoHttps.Azure;

/// <summary>
/// Answers ACME <c>dns-01</c> challenges by publishing TXT records in an Azure DNS zone.
/// </summary>
public sealed class AzureDnsChallengeProvider : IDnsChallengeProvider
{
    private const int MaxAttempts = 5;

    private readonly IAzureDnsClient _client;
    private readonly AzureDnsOptions _options;

    internal AzureDnsChallengeProvider(IAzureDnsClient client, IOptions<AzureDnsOptions> options)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(options);

        _client = client;
        _options = options.Value;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Azure DNS keeps every TXT value at a name in one record set, and writing the set replaces all of
    /// it. Other values can be there for good reasons: a wildcard and its apex in one order both use
    /// <c>_acme-challenge</c> at the apex, and so does another client ordering for the same name. So the
    /// value is added to what is there, and the write is conditional on the set being unchanged since
    /// it was read, so a value someone else adds in between is not lost.
    /// </remarks>
    public async Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string name = RelativeName(recordName);

        for (int attempt = 1; ; attempt++)
        {
            AzureTxtRecordSet? existing = await _client.GetTxtAsync(name, cancellationToken);
            if (existing is not null && existing.Records.Any(record => Holds(record, recordValue)))
            {
                return;
            }

            // An existing set keeps its own TTL, which belongs to whoever created it.
            IReadOnlyList<IReadOnlyList<string>> records = existing is null
                ? [[recordValue]]
                : [.. existing.Records, [recordValue]];
            long ttl = existing?.Ttl ?? _options.RecordTtlSeconds;

            if (await _client.TryWriteTxtAsync(name, ttl, records, existing?.ETag, cancellationToken))
            {
                return;
            }

            ThrowIfOutOfAttempts(attempt, name);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Only the value this provider added is taken out. The set is deleted only when that value was the
    /// last one in it, and a set that does not hold the value is left as it is.
    /// </remarks>
    public async Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken)
    {
        string name = RelativeName(recordName);

        for (int attempt = 1; ; attempt++)
        {
            AzureTxtRecordSet? existing = await _client.GetTxtAsync(name, cancellationToken);
            if (existing is null || !existing.Records.Any(record => Holds(record, recordValue)))
            {
                return;
            }

            IReadOnlyList<IReadOnlyList<string>> remaining = [.. existing.Records.Where(record => !Holds(record, recordValue))];

            bool done = remaining.Count == 0
                ? await _client.TryDeleteTxtAsync(name, existing.ETag, cancellationToken)
                : await _client.TryWriteTxtAsync(name, existing.Ttl, remaining, existing.ETag, cancellationToken);

            if (done)
            {
                return;
            }

            ThrowIfOutOfAttempts(attempt, name);
        }
    }

    private static bool Holds(IReadOnlyList<string> record, string value) =>
        string.Equals(string.Concat(record), value, StringComparison.Ordinal);

    // Each retry rereads the set, so this only gives up when something keeps changing it faster than
    // a read and a write take, which is not a race worth winning by retrying forever.
    private static void ThrowIfOutOfAttempts(int attempt, string name)
    {
        if (attempt >= MaxAttempts)
        {
            throw new InvalidOperationException(
                $"The TXT record set '{name}' changed {MaxAttempts} times while AutoHttps was updating it, so the update was abandoned.");
        }
    }

    /// <summary>
    /// The record name relative to the zone, which is what Azure DNS addresses records by. The apex is
    /// <c>@</c>; a record under the zone drops the zone suffix.
    /// </summary>
    private string RelativeName(string recordName)
    {
        string zone = (_options.ZoneName ?? throw new InvalidOperationException("AzureDnsOptions.ZoneName is required."))
            .TrimEnd('.');
        string name = recordName.TrimEnd('.');

        if (string.Equals(name, zone, StringComparison.OrdinalIgnoreCase))
        {
            return "@";
        }

        if (name.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase))
        {
            return name[..^(zone.Length + 1)];
        }

        throw new InvalidOperationException($"'{recordName}' is not within the configured Azure DNS zone '{zone}'.");
    }
}
