using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Azure.ResourceManager.Dns.Models;

namespace AutoHttps.Azure;

/// <summary>Translates the provider's needs into Azure DNS SDK calls against one configured zone.</summary>
internal sealed class AzureDnsClientAdapter : IAzureDnsClient
{
    private const int PreconditionFailed = 412;
    private const int NotFound = 404;

    private readonly DnsZoneResource _zone;

    public AzureDnsClientAdapter(AzureDnsOptions options, TokenCredential credential)
    {
        Require(options.SubscriptionId, nameof(AzureDnsOptions.SubscriptionId));
        Require(options.ResourceGroupName, nameof(AzureDnsOptions.ResourceGroupName));
        Require(options.ZoneName, nameof(AzureDnsOptions.ZoneName));

        var arm = new ArmClient(credential);
        ResourceIdentifier zoneId = DnsZoneResource.CreateResourceIdentifier(
            options.SubscriptionId, options.ResourceGroupName, options.ZoneName);

        _zone = arm.GetDnsZoneResource(zoneId);
    }

    public async Task<AzureTxtRecordSet?> GetTxtAsync(string relativeRecordName, CancellationToken cancellationToken)
    {
        DnsTxtRecordResource? resource = await FindAsync(relativeRecordName, cancellationToken);
        if (resource is null)
        {
            return null;
        }

        DnsTxtRecordData data = resource.Data;
        IReadOnlyList<IReadOnlyList<string>> records = [.. data.DnsTxtRecords.Select(static record => (IReadOnlyList<string>)[.. record.Values])];

        return new AzureTxtRecordSet(data.TtlInSeconds ?? 0, records, data.ETag?.ToString() ?? string.Empty);
    }

    public async Task<bool> TryWriteTxtAsync(
        string relativeRecordName,
        long ttl,
        IReadOnlyList<IReadOnlyList<string>> records,
        string? etag,
        CancellationToken cancellationToken)
    {
        var data = new DnsTxtRecordData { TtlInSeconds = ttl };
        foreach (IReadOnlyList<string> pieces in records)
        {
            var record = new DnsTxtRecordInfo();
            foreach (string piece in pieces)
            {
                record.Values.Add(piece);
            }

            data.DnsTxtRecords.Add(record);
        }

        try
        {
            // If-Match on the etag that was read, or If-None-Match: * when there was no set, so a change
            // made by anyone else in between fails the write instead of being overwritten.
            await _zone.GetDnsTxtRecords().CreateOrUpdateAsync(
                WaitUntil.Completed,
                relativeRecordName,
                data,
                ifMatch: etag is null ? null : new ETag(etag),
                ifNoneMatch: etag is null ? "*" : null,
                cancellationToken: cancellationToken);

            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == PreconditionFailed)
        {
            return false;
        }
    }

    public async Task<bool> TryDeleteTxtAsync(string relativeRecordName, string etag, CancellationToken cancellationToken)
    {
        DnsTxtRecordResource? resource = await FindAsync(relativeRecordName, cancellationToken);
        if (resource is null)
        {
            return true;
        }

        try
        {
            await resource.DeleteAsync(WaitUntil.Completed, new ETag(etag), cancellationToken);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == PreconditionFailed)
        {
            return false;
        }
        catch (RequestFailedException ex) when (ex.Status == NotFound)
        {
            return true;
        }
    }

    private async Task<DnsTxtRecordResource?> FindAsync(string relativeRecordName, CancellationToken cancellationToken)
    {
        try
        {
            Response<DnsTxtRecordResource> response = await _zone.GetDnsTxtRecords().GetAsync(relativeRecordName, cancellationToken);
            return response.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == NotFound)
        {
            return null;
        }
    }

    private static void Require(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"AzureDnsOptions.{name} is required.");
        }
    }
}
