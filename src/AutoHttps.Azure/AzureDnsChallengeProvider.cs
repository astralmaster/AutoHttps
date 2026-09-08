using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace AutoHttps.Azure;

/// <summary>
/// Answers ACME <c>dns-01</c> challenges by publishing TXT records in an Azure DNS zone.
/// </summary>
public sealed class AzureDnsChallengeProvider : IDnsChallengeProvider
{
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
    public Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
        _client.UpsertTxtAsync(RelativeName(recordName), _options.RecordTtlSeconds, recordValue, cancellationToken);

    /// <inheritdoc />
    public Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
        _client.DeleteTxtAsync(RelativeName(recordName), cancellationToken);

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
