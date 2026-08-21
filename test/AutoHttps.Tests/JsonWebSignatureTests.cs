using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AutoHttps.Acme;
using AutoHttps.Internal;
using Xunit;

namespace AutoHttps.Tests;

public class JsonWebSignatureTests
{
    private static readonly Uri Url = new("https://acme.example.com/new-order");

    [Fact]
    public void Encode_ProducesFlattenedJsonSerialization()
    {
        using var key = AcmeKey.CreateEcdsa();

        using JsonDocument jws = JsonDocument.Parse(
            JsonWebSignature.Encode(key, Url, "nonce-1", keyId: "https://acme.example.com/acct/1", "{}"));

        Assert.Equal(3, System.Linq.Enumerable.Count(jws.RootElement.EnumerateObject()));
        Assert.True(jws.RootElement.TryGetProperty("protected", out _));
        Assert.True(jws.RootElement.TryGetProperty("payload", out _));
        Assert.True(jws.RootElement.TryGetProperty("signature", out _));
    }

    [Fact]
    public void Encode_UsesKidWhenTheAccountIsKnown()
    {
        using var key = AcmeKey.CreateEcdsa();

        JsonElement header = ReadProtectedHeader(
            JsonWebSignature.Encode(key, Url, "nonce-1", keyId: "https://acme.example.com/acct/1", "{}"));

        Assert.Equal("ES256", header.GetProperty("alg").GetString());
        Assert.Equal("https://acme.example.com/acct/1", header.GetProperty("kid").GetString());
        Assert.Equal("nonce-1", header.GetProperty("nonce").GetString());
        Assert.Equal(Url.AbsoluteUri, header.GetProperty("url").GetString());
        Assert.False(header.TryGetProperty("jwk", out _));
    }

    [Fact]
    public void Encode_EmbedsTheJwkWhenThereIsNoAccountYet()
    {
        using var key = AcmeKey.CreateEcdsa();

        JsonElement header = ReadProtectedHeader(JsonWebSignature.Encode(key, Url, "nonce-1", keyId: null, "{}"));

        Assert.False(header.TryGetProperty("kid", out _));
        Assert.Equal("EC", header.GetProperty("jwk").GetProperty("kty").GetString());
        Assert.Equal(key.Jwk, header.GetProperty("jwk").GetRawText());
    }

    [Fact]
    public void Encode_LeavesThePayloadEmptyForPostAsGet()
    {
        using var key = AcmeKey.CreateEcdsa();

        using JsonDocument jws = JsonDocument.Parse(
            JsonWebSignature.Encode(key, Url, "nonce-1", keyId: "https://acme.example.com/acct/1", string.Empty));

        Assert.Equal(string.Empty, jws.RootElement.GetProperty("payload").GetString());
    }

    [Fact]
    public void Encode_SignsTheProtectedHeaderAndPayloadJoinedByADot()
    {
        using var key = AcmeKey.CreateEcdsa();

        using JsonDocument jws = JsonDocument.Parse(
            JsonWebSignature.Encode(key, Url, "nonce-1", keyId: "https://acme.example.com/acct/1", """{"a":1}"""));

        string protectedHeader = jws.RootElement.GetProperty("protected").GetString()!;
        string payload = jws.RootElement.GetProperty("payload").GetString()!;
        byte[] signature = Base64Url.Decode(jws.RootElement.GetProperty("signature").GetString()!);

        Assert.True(key.Verify(Encoding.ASCII.GetBytes(protectedHeader + "." + payload), signature));
        Assert.False(key.Verify(Encoding.ASCII.GetBytes(protectedHeader + payload), signature));
    }

    [Fact]
    public void Encode_EscapesUrlsThatWouldOtherwiseBreakTheHeaderJson()
    {
        using var key = AcmeKey.CreateEcdsa();
        var url = new Uri("https://acme.example.com/order?a=1&b=\"two\"");

        JsonElement header = ReadProtectedHeader(JsonWebSignature.Encode(key, url, "nonce-1", keyId: "kid", "{}"));

        Assert.Equal(url.AbsoluteUri, header.GetProperty("url").GetString());
    }

    [Fact]
    public void EncodeHmac_ProducesAVerifiableExternalAccountBinding()
    {
        byte[] hmacKey = RandomNumberGenerator.GetBytes(32);
        using var accountKey = AcmeKey.CreateEcdsa();

        string binding = JsonWebSignature.EncodeHmac(hmacKey, "eab-kid", Url, accountKey.Jwk);

        using JsonDocument jws = JsonDocument.Parse(binding);
        string protectedHeader = jws.RootElement.GetProperty("protected").GetString()!;
        string payload = jws.RootElement.GetProperty("payload").GetString()!;
        byte[] signature = Base64Url.Decode(jws.RootElement.GetProperty("signature").GetString()!);

        byte[] expected = HMACSHA256.HashData(hmacKey, Encoding.ASCII.GetBytes(protectedHeader + "." + payload));
        Assert.Equal(expected, signature);

        using JsonDocument header = JsonDocument.Parse(Encoding.UTF8.GetString(Base64Url.Decode(protectedHeader)));
        Assert.Equal("HS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("eab-kid", header.RootElement.GetProperty("kid").GetString());
        Assert.Equal(accountKey.Jwk, Encoding.UTF8.GetString(Base64Url.Decode(payload)));
    }

    private static JsonElement ReadProtectedHeader(string jws)
    {
        using JsonDocument envelope = JsonDocument.Parse(jws);
        string encoded = envelope.RootElement.GetProperty("protected").GetString()!;

        return JsonDocument.Parse(Encoding.UTF8.GetString(Base64Url.Decode(encoded))).RootElement.Clone();
    }
}
