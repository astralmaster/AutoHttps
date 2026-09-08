using System;
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

    public async Task UpsertTxtAsync(string relativeRecordName, long ttl, string value, CancellationToken cancellationToken)
    {
        var data = new DnsTxtRecordData { TtlInSeconds = ttl };
        var record = new DnsTxtRecordInfo();
        record.Values.Add(value);
        data.DnsTxtRecords.Add(record);

        await _zone.GetDnsTxtRecords().CreateOrUpdateAsync(
            WaitUntil.Completed, relativeRecordName, data, cancellationToken: cancellationToken);
    }

    public async Task DeleteTxtAsync(string relativeRecordName, CancellationToken cancellationToken)
    {
        DnsTxtRecordCollection records = _zone.GetDnsTxtRecords();

        if (await records.ExistsAsync(relativeRecordName, cancellationToken: cancellationToken))
        {
            DnsTxtRecordResource resource = await records.GetAsync(relativeRecordName, cancellationToken: cancellationToken);
            await resource.DeleteAsync(WaitUntil.Completed, cancellationToken: cancellationToken);
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
