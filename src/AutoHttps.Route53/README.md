# AutoHttps.Route53

AWS Route 53 DNS provider for [AutoHttps](https://github.com/astralmaster/AutoHttps). It answers
`dns-01` challenges, including wildcards, by publishing TXT records in a Route 53 hosted zone.

```
dotnet add package AutoHttps.Route53
```

## Use

The provider needs permission to change resource record sets in the zone, and to list hosted zones if
you let it find the zone from the record name:

```csharp
builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add("*.example.com");
    options.DomainNames.Add("example.com");
    options.EmailAddress = "admin@example.com";
    options.AcceptTermsOfService = true;
    options.PreferredChallengeType = "dns-01";
})
.UseRoute53();
```

Credentials and region follow the AWS SDK's usual resolution: environment variables, the shared
config, or an instance role. Set them explicitly if you need to:

```csharp
.UseRoute53(options =>
{
    options.HostedZoneId = "Z123456ABCDEFG";
    options.Region = "us-east-1";
    options.AccessKeyId = builder.Configuration["Aws:AccessKeyId"];
    options.SecretAccessKey = builder.Configuration["Aws:SecretAccessKey"];
});
```

## Options

| Option | Default | What it does |
|---|---|---|
| `HostedZoneId` | *(discovered)* | The zone to publish in. Leave unset to find it from the record name. |
| `AccessKeyId` / `SecretAccessKey` | *(default chain)* | Explicit credentials. Set both or neither, because one without the other is refused at startup. |
| `Region` | *(SDK default)* | The region to sign for, for example `us-east-1`. |
| `RecordTtlSeconds` | 60 | TTL for the challenge records. A record set that already exists keeps its own. |

Route 53 keeps every TXT value at a name in one record set, and a wildcard with its apex, or another
client ordering for the same name, puts more than one value at `_acme-challenge`. The provider adds its
value to whatever is there and later removes only that value, deleting the set only when nothing else
is left in it. Each change names the set as it was read, so Route 53 refuses it if another client
changed the set in between, and the provider then reads it again and retries, up to five times.

After publishing a value the provider waits, for up to two minutes, until Route 53 reports the change on
every name server for the zone (`INSYNC`). AWS says that generally takes under a minute, and asking for
validation before then can fail it.

A minimum policy grants `route53:ChangeResourceRecordSets` and `route53:ListResourceRecordSets` on the
hosted zone, `route53:GetChange` to wait for a change to apply, plus `route53:ListHostedZonesByName`
when the zone is discovered. The record changes are `CREATE` and `DELETE` (not `UPSERT`), so a policy
that narrows `route53:ChangeResourceRecordSetsActions` has to allow those two, and one that names
`route53:ChangeResourceRecordSetsRecordTypes` has to allow `TXT`.
