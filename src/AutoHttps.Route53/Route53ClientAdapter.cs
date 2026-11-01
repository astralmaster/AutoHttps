using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Amazon.Route53;
using Amazon.Route53.Model;

namespace AutoHttps.Route53;

/// <summary>Translates the provider's needs into AWS Route 53 SDK calls.</summary>
internal sealed class Route53ClientAdapter : IRoute53Client, IDisposable
{
    private readonly IAmazonRoute53 _route53;

    public Route53ClientAdapter(IAmazonRoute53 route53) => _route53 = route53;

    public async Task<string?> FindZoneIdAsync(string dnsName, CancellationToken cancellationToken)
    {
        ListHostedZonesByNameResponse response = await _route53.ListHostedZonesByNameAsync(
            new ListHostedZonesByNameRequest { DNSName = dnsName }, cancellationToken);

        foreach (HostedZone zone in response.HostedZones ?? [])
        {
            bool isPrivate = zone.Config?.PrivateZone ?? false;
            string zoneName = (zone.Name ?? string.Empty).TrimEnd('.');

            if (!isPrivate && string.Equals(zoneName, dnsName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
            {
                return StripPrefix(zone.Id ?? string.Empty);
            }
        }

        return null;
    }

    public async Task<Route53TxtRecord?> GetTxtRecordAsync(string zoneId, string recordName, CancellationToken cancellationToken)
    {
        string name = Normalize(recordName);

        ListResourceRecordSetsResponse response = await _route53.ListResourceRecordSetsAsync(
            new ListResourceRecordSetsRequest
            {
                HostedZoneId = zoneId,
                StartRecordName = name,
                StartRecordType = RRType.TXT,
            },
            cancellationToken);

        foreach (ResourceRecordSet set in response.ResourceRecordSets ?? [])
        {
            string setName = (set.Name ?? string.Empty).TrimEnd('.');
            if (set.Type == RRType.TXT && string.Equals(setName, name.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
            {
                List<string> values = (set.ResourceRecords ?? [])
                    .Select(record => record.Value ?? string.Empty)
                    .Where(value => value.Length > 0)
                    .ToList();

                return values.Count == 0 ? null : new Route53TxtRecord(set.TTL ?? 0, values);
            }
        }

        return null;
    }

    public async Task<Route53ChangeResult> TryReplaceTxtAsync(
        string zoneId,
        string recordName,
        Route53TxtRecord? expected,
        Route53TxtRecord? replacement,
        CancellationToken cancellationToken)
    {
        var changes = new List<Change>();

        if (expected is not null)
        {
            changes.Add(new Change { Action = ChangeAction.DELETE, ResourceRecordSet = ToRecordSet(recordName, expected) });
        }

        if (replacement is not null)
        {
            changes.Add(new Change { Action = ChangeAction.CREATE, ResourceRecordSet = ToRecordSet(recordName, replacement) });
        }

        var request = new ChangeResourceRecordSetsRequest
        {
            HostedZoneId = zoneId,
            ChangeBatch = new ChangeBatch { Changes = changes },
        };

        try
        {
            ChangeResourceRecordSetsResponse response = await _route53.ChangeResourceRecordSetsAsync(request, cancellationToken);
            return new Route53ChangeResult(response.ChangeInfo?.Id ?? string.Empty, null);
        }
        catch (InvalidChangeBatchException ex)
        {
            // What a set changed by someone else since it was read looks like: the DELETE no longer
            // matches it, or the CREATE finds one. The caller reads the set again and retries.
            return new Route53ChangeResult(null, ex.Message);
        }
    }

    private static ResourceRecordSet ToRecordSet(string recordName, Route53TxtRecord record) => new()
    {
        Name = Normalize(recordName),
        Type = RRType.TXT,
        TTL = record.Ttl,
        ResourceRecords = record.Values.Select(value => new ResourceRecord { Value = value }).ToList(),
    };

    public async Task<bool> IsChangeInSyncAsync(string changeId, CancellationToken cancellationToken)
    {
        // The id comes back as "/change/C..." and the request takes the bare id.
        string id = changeId.StartsWith("/change/", StringComparison.Ordinal) ? changeId["/change/".Length..] : changeId;

        GetChangeResponse response = await _route53.GetChangeAsync(new GetChangeRequest { Id = id }, cancellationToken);
        return response.ChangeInfo?.Status == ChangeStatus.INSYNC;
    }

    public void Dispose() => _route53.Dispose();

    private static string Normalize(string name) => name.EndsWith('.') ? name : name + ".";

    private static string StripPrefix(string zoneId) =>
        zoneId.StartsWith("/hostedzone/", StringComparison.Ordinal) ? zoneId["/hostedzone/".Length..] : zoneId;
}
