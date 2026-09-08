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
| `AccessKeyId` / `SecretAccessKey` | *(default chain)* | Explicit credentials. |
| `Region` | *(SDK default)* | The region to sign for, for example `us-east-1`. |
| `RecordTtlSeconds` | 60 | TTL for the challenge records. |

A minimum policy grants `route53:ChangeResourceRecordSets` and `route53:ListResourceRecordSets` on the
hosted zone, plus `route53:ListHostedZonesByName` when the zone is discovered.
