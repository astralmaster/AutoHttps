using System.Text.Json;
using System.Text.Json.Serialization;

namespace AutoHttps.Acme;

[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    ReadCommentHandling = JsonCommentHandling.Skip)]
[JsonSerializable(typeof(AcmeDirectory))]
[JsonSerializable(typeof(AcmeAccountResource))]
[JsonSerializable(typeof(AcmeOrderResource))]
[JsonSerializable(typeof(AcmeAuthorizationResource))]
[JsonSerializable(typeof(AcmeChallengeResource))]
[JsonSerializable(typeof(AcmeProblem))]
[JsonSerializable(typeof(AcmeRenewalInfoResource))]
[JsonSerializable(typeof(AcmeEmptyResource))]
internal sealed partial class AcmeJsonContext : JsonSerializerContext;
