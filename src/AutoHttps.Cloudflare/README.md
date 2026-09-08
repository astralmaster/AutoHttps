# AutoHttps.Cloudflare

Cloudflare DNS provider for [AutoHttps](https://github.com/astralmaster/AutoHttps). It answers
`dns-01` challenges, including wildcards, by publishing TXT records through the Cloudflare API.

```
dotnet add package AutoHttps.Cloudflare
```

## Use

Create a scoped Cloudflare API token with the Zone.DNS Edit permission for the zones you validate,
then:

```csharp
builder.Services.AddAutoHttps(options =>
{
    options.DomainNames.Add("*.example.com");
    options.DomainNames.Add("example.com");
    options.EmailAddress = "admin@example.com";
    options.AcceptTermsOfService = true;
    options.PreferredChallengeType = "dns-01";
})
.UseCloudflareDns(builder.Configuration["Cloudflare:ApiToken"]!);
```

The provider finds the zone from the record name, so a token that can list zones needs no further
configuration. If the token is scoped to a single zone and cannot list, set the zone id:

```csharp
.UseCloudflareDns(options =>
{
    options.ApiToken = builder.Configuration["Cloudflare:ApiToken"]!;
    options.ZoneId = "your-zone-id";
});
```

## Options

| Option | Default | What it does |
|---|---|---|
| `ApiToken` | *(required)* | Cloudflare API token with Zone.DNS Edit. |
| `ZoneId` | *(discovered)* | The zone to publish in. Leave unset to find it from the record name. |
| `RecordTtlSeconds` | 60 | TTL for the challenge records. |

Pair this with `DnsPropagationResolver` on the AutoHttps options to have the challenge wait until the
record is visible before validation. See the main README.
