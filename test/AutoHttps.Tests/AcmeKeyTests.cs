using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AutoHttps.Acme;
using AutoHttps.Internal;
using Xunit;

namespace AutoHttps.Tests;

public class AcmeKeyTests
{
    // RFC 7638 section 3.1 publishes this key together with its expected thumbprint, which pins the
    // member ordering and the absence of whitespace in the canonical form.
    private const string Rfc7638CanonicalJwk =
        """{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}""";

    private const string Rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    [Fact]
    public void Thumbprint_MatchesTheRfc7638KnownAnswer() =>
        Assert.Equal(Rfc7638Thumbprint, AcmeKey.ComputeThumbprint(Rfc7638CanonicalJwk));

    [Fact]
    public void EcdsaJwk_HasTheCanonicalMemberOrderAndNoWhitespace()
    {
        using var key = AcmeKey.CreateEcdsa();

        Assert.Matches(
            new Regex("""^\{"crv":"P-256","kty":"EC","x":"[A-Za-z0-9_-]+","y":"[A-Za-z0-9_-]+"\}$"""),
            key.Jwk);
    }

    [Fact]
    public void RsaJwk_HasTheCanonicalMemberOrderAndNoWhitespace()
    {
        using var key = AcmeKey.CreateRsa();

        Assert.Matches(
            new Regex("""^\{"e":"[A-Za-z0-9_-]+","kty":"RSA","n":"[A-Za-z0-9_-]+"\}$"""),
            key.Jwk);
    }

    [Theory]
    [InlineData(256, "P-256", "ES256", 32)]
    [InlineData(384, "P-384", "ES384", 48)]
    [InlineData(521, "P-521", "ES512", 66)]
    public void EcdsaJwk_PadsCoordinatesToTheFieldSize(int keySize, string curve, string algorithm, int coordinateLength)
    {
        using var key = AcmeKey.CreateEcdsa(keySize);
        using JsonDocument jwk = JsonDocument.Parse(key.Jwk);

        Assert.Equal(algorithm, key.SignatureAlgorithm);
        Assert.Equal(curve, jwk.RootElement.GetProperty("crv").GetString());
        Assert.Equal(coordinateLength, Base64Url.Decode(jwk.RootElement.GetProperty("x").GetString()!).Length);
        Assert.Equal(coordinateLength, Base64Url.Decode(jwk.RootElement.GetProperty("y").GetString()!).Length);
    }

    [Fact]
    public void EcdsaSignature_IsRawConcatenatedRAndSRatherThanDer()
    {
        using var key = AcmeKey.CreateEcdsa();
        byte[] signature = key.Sign("payload"u8);

        // A DER encoded ECDSA signature starts with 0x30 and varies in length; JOSE requires a fixed
        // width R||S, which is 64 bytes for P-256.
        Assert.Equal(64, signature.Length);
        Assert.True(key.Verify("payload"u8, signature));
    }

    [Fact]
    public void Verify_RejectsATamperedPayload()
    {
        using var key = AcmeKey.CreateEcdsa();
        byte[] signature = key.Sign("payload"u8);

        Assert.False(key.Verify("payloae"u8, signature));
    }

    [Fact]
    public void RsaKey_SignsWithRs256()
    {
        using var key = AcmeKey.CreateRsa();
        byte[] signature = key.Sign("payload"u8);

        Assert.Equal("RS256", key.SignatureAlgorithm);
        Assert.Equal(256, signature.Length);
        Assert.True(key.Verify("payload"u8, signature));
    }

    [Fact]
    public void ImportPem_RestoresAnEcdsaKeyExactly()
    {
        using var original = AcmeKey.CreateEcdsa();
        using AcmeKey restored = AcmeKey.ImportPem(original.ExportPem());

        Assert.Equal(original.Jwk, restored.Jwk);
        Assert.Equal(original.Thumbprint, restored.Thumbprint);
        Assert.True(original.Verify("payload"u8, restored.Sign("payload"u8)));
    }

    [Fact]
    public void ImportPem_RestoresAnRsaKeyExactly()
    {
        using var original = AcmeKey.CreateRsa();
        using AcmeKey restored = AcmeKey.ImportPem(original.ExportPem());

        Assert.Equal(original.Jwk, restored.Jwk);
        Assert.Equal("RS256", restored.SignatureAlgorithm);
    }

    [Fact]
    public void ImportPem_RejectsGarbage() =>
        Assert.ThrowsAny<Exception>(() => AcmeKey.ImportPem("-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----"));

    [Fact]
    public void KeyAuthorization_IsTokenDotThumbprint()
    {
        using var key = AcmeKey.CreateEcdsa();

        Assert.Equal("a-token." + key.Thumbprint, key.GetKeyAuthorization("a-token"));
    }

    [Fact]
    public void DnsRecordValue_IsTheBase64UrlSha256OfTheKeyAuthorization()
    {
        using var key = AcmeKey.CreateEcdsa();
        string expected = Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(key.GetKeyAuthorization("a-token"))));

        Assert.Equal(expected, key.GetDnsRecordValue("a-token"));
        Assert.Equal(43, key.GetDnsRecordValue("a-token").Length);
    }

    [Fact]
    public void CreateRsa_RejectsKeysBelowTheMinimumSize() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => AcmeKey.CreateRsa(1024));
}
