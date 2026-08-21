using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AutoHttps.IntegrationTests.TestCa;

internal sealed record VerifiedRequest(string Payload, string? KeyId, JsonElement? Jwk, string Nonce);

internal sealed class JwsVerificationException : Exception
{
    public JwsVerificationException(string message, string errorType = "urn:ietf:params:acme:error:malformed")
        : base(message) => ErrorType = errorType;

    public string ErrorType { get; }
}

/// <summary>
/// Verifies the JSON Web Signatures the client sends. This deliberately re-implements decoding and
/// canonicalisation rather than reusing the library's helpers, so that a defect in the library is
/// not mirrored by the code checking it.
/// </summary>
internal static class TestJws
{
    public static VerifiedRequest Verify(string body, Uri requestUrl, Func<string, JsonElement?> resolveAccountKey)
    {
        using JsonDocument envelope = Parse(body);
        JsonElement root = envelope.RootElement;

        string protectedHeader = Require(root, "protected");
        string payload = root.TryGetProperty("payload", out JsonElement payloadElement)
            ? payloadElement.GetString() ?? string.Empty
            : string.Empty;
        string signature = Require(root, "signature");

        using JsonDocument header = Parse(Encoding.UTF8.GetString(Decode(protectedHeader)));
        JsonElement headerRoot = header.RootElement;

        string algorithm = headerRoot.TryGetProperty("alg", out JsonElement alg)
            ? alg.GetString() ?? throw new JwsVerificationException("The protected header has no alg.")
            : throw new JwsVerificationException("The protected header has no alg.");

        string url = headerRoot.TryGetProperty("url", out JsonElement urlElement)
            ? urlElement.GetString() ?? string.Empty
            : throw new JwsVerificationException("The protected header has no url.");

        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? declared) ||
            !string.Equals(declared.AbsolutePath, requestUrl.AbsolutePath, StringComparison.Ordinal))
        {
            throw new JwsVerificationException($"The protected header url '{url}' does not match the request '{requestUrl}'.");
        }

        string nonce = headerRoot.TryGetProperty("nonce", out JsonElement nonceElement)
            ? nonceElement.GetString() ?? string.Empty
            : throw new JwsVerificationException("The protected header has no nonce.", "urn:ietf:params:acme:error:badNonce");

        bool hasJwk = headerRoot.TryGetProperty("jwk", out JsonElement jwk);
        bool hasKid = headerRoot.TryGetProperty("kid", out JsonElement kid);

        if (hasJwk == hasKid)
        {
            throw new JwsVerificationException("The protected header must carry exactly one of jwk and kid.");
        }

        string? keyId = hasKid ? kid.GetString() : null;
        JsonElement key = hasJwk
            ? jwk.Clone()
            : resolveAccountKey(keyId!) ?? throw new JwsVerificationException(
                "Unknown account.", "urn:ietf:params:acme:error:accountDoesNotExist");

        byte[] signingInput = Encoding.ASCII.GetBytes(protectedHeader + "." + payload);

        if (!VerifySignature(key, algorithm, signingInput, Decode(signature)))
        {
            throw new JwsVerificationException("The JWS signature is not valid.");
        }

        string decodedPayload = payload.Length == 0 ? string.Empty : Encoding.UTF8.GetString(Decode(payload));
        return new VerifiedRequest(decodedPayload, keyId, hasJwk ? key : null, nonce);
    }

    public static bool VerifyHmac(byte[] hmacKey, string body, out string payload)
    {
        payload = string.Empty;

        using JsonDocument envelope = Parse(body);
        JsonElement root = envelope.RootElement;

        string protectedHeader = Require(root, "protected");
        string encodedPayload = Require(root, "payload");
        string signature = Require(root, "signature");

        byte[] expected = HMACSHA256.HashData(hmacKey, Encoding.ASCII.GetBytes(protectedHeader + "." + encodedPayload));
        if (!CryptographicOperations.FixedTimeEquals(expected, Decode(signature)))
        {
            return false;
        }

        payload = Encoding.UTF8.GetString(Decode(encodedPayload));
        return true;
    }

    public static string Thumbprint(JsonElement jwk) =>
        Encode(SHA256.HashData(Encoding.UTF8.GetBytes(Canonicalize(jwk))));

    public static string Canonicalize(JsonElement jwk)
    {
        string keyType = jwk.GetProperty("kty").GetString()!;

        return keyType switch
        {
            "EC" => $"{{\"crv\":\"{jwk.GetProperty("crv").GetString()}\",\"kty\":\"EC\"," +
                    $"\"x\":\"{jwk.GetProperty("x").GetString()}\",\"y\":\"{jwk.GetProperty("y").GetString()}\"}}",
            "RSA" => $"{{\"e\":\"{jwk.GetProperty("e").GetString()}\",\"kty\":\"RSA\"," +
                     $"\"n\":\"{jwk.GetProperty("n").GetString()}\"}}",
            _ => throw new JwsVerificationException($"Unsupported key type '{keyType}'."),
        };
    }

    public static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            0 => string.Empty,
            _ => throw new JwsVerificationException("Value is not valid base64url."),
        };

        return Convert.FromBase64String(padded);
    }

    private static bool VerifySignature(JsonElement jwk, string algorithm, byte[] data, byte[] signature)
    {
        string keyType = jwk.GetProperty("kty").GetString()!;

        if (keyType == "EC")
        {
            if (algorithm is not ("ES256" or "ES384" or "ES512"))
            {
                throw new JwsVerificationException($"Algorithm '{algorithm}' does not match an EC key.");
            }

            var parameters = new ECParameters
            {
                Curve = jwk.GetProperty("crv").GetString() switch
                {
                    "P-256" => ECCurve.NamedCurves.nistP256,
                    "P-384" => ECCurve.NamedCurves.nistP384,
                    "P-521" => ECCurve.NamedCurves.nistP521,
                    var curve => throw new JwsVerificationException($"Unsupported curve '{curve}'."),
                },
                Q = new ECPoint
                {
                    X = Decode(jwk.GetProperty("x").GetString()!),
                    Y = Decode(jwk.GetProperty("y").GetString()!),
                },
            };

            using ECDsa ecdsa = ECDsa.Create(parameters);
            return ecdsa.VerifyData(data, signature, HashFor(algorithm), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        if (keyType == "RSA")
        {
            if (algorithm != "RS256")
            {
                throw new JwsVerificationException($"Algorithm '{algorithm}' does not match an RSA key.");
            }

            var parameters = new RSAParameters
            {
                Modulus = Decode(jwk.GetProperty("n").GetString()!),
                Exponent = Decode(jwk.GetProperty("e").GetString()!),
            };

            using RSA rsa = RSA.Create(parameters);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        throw new JwsVerificationException($"Unsupported key type '{keyType}'.");
    }

    private static HashAlgorithmName HashFor(string algorithm) => algorithm switch
    {
        "ES256" => HashAlgorithmName.SHA256,
        "ES384" => HashAlgorithmName.SHA384,
        _ => HashAlgorithmName.SHA512,
    };

    private static JsonDocument Parse(string json)
    {
        try
        {
            return JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new JwsVerificationException("The request body is not valid JSON: " + ex.Message);
        }
    }

    private static string Require(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.GetString() is { } text
            ? text
            : throw new JwsVerificationException($"The JWS has no '{name}' member.");
}
