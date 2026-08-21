using System;
using System.Text;
using AutoHttps.Internal;
using Xunit;

namespace AutoHttps.Tests;

public class Base64UrlTests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "Zg")]
    [InlineData("fo", "Zm8")]
    [InlineData("foo", "Zm9v")]
    [InlineData("foob", "Zm9vYg")]
    [InlineData("fooba", "Zm9vYmE")]
    [InlineData("foobar", "Zm9vYmFy")]
    public void Encode_MatchesRfc4648VectorsWithoutPadding(string input, string expected) =>
        Assert.Equal(expected, Base64Url.Encode(Encoding.ASCII.GetBytes(input)));

    [Fact]
    public void Encode_UsesUrlSafeAlphabet()
    {
        // 0xFB 0xFF encodes to "+/8=" in standard base64, which must become "-_8" here.
        string encoded = Base64Url.Encode([0xFB, 0xFF, 0xFF]);

        Assert.Equal("-___", encoded);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.DoesNotContain('=', encoded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(191)]
    [InlineData(192)]
    [InlineData(193)]
    [InlineData(4096)]
    public void RoundTrip_PreservesBytesAcrossTheStackallocBoundary(int length)
    {
        byte[] original = new byte[length];
        for (int i = 0; i < length; i++)
        {
            original[i] = (byte)(i * 7 % 256);
        }

        Assert.Equal(original, Base64Url.Decode(Base64Url.Encode(original)));
    }

    [Fact]
    public void Decode_AcceptsValueEncodedByAnIndependentImplementation()
    {
        byte[] payload = Encoding.UTF8.GetBytes("{\"alg\":\"ES256\"}");
        string encoded = Convert.ToBase64String(payload).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Assert.Equal(payload, Base64Url.Decode(encoded));
    }

    [Fact]
    public void Decode_RejectsImpossibleLength() =>
        Assert.Throws<FormatException>(() => Base64Url.Decode("Zg9vYmFya"[..5]));

    [Fact]
    public void Decode_RejectsNull() =>
        Assert.Throws<ArgumentNullException>(() => Base64Url.Decode(null!));
}
