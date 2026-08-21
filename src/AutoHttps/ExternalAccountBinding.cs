using System;
using AutoHttps.Internal;

namespace AutoHttps;

/// <summary>
/// Credentials that bind a new ACME account to an existing account at the certificate authority.
/// Required by authorities such as ZeroSSL, Google Trust Services and Sectigo.
/// </summary>
public sealed class ExternalAccountBinding
{
    private readonly byte[] _hmacKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalAccountBinding"/> class.
    /// </summary>
    /// <param name="keyId">The key identifier issued by the certificate authority.</param>
    /// <param name="hmacKey">The HMAC key issued by the certificate authority, encoded as base64url.</param>
    public ExternalAccountBinding(string keyId, string hmacKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(hmacKey);

        KeyId = keyId;
        _hmacKey = DecodeKey(hmacKey);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalAccountBinding"/> class.
    /// </summary>
    /// <param name="keyId">The key identifier issued by the certificate authority.</param>
    /// <param name="hmacKey">The raw HMAC key issued by the certificate authority.</param>
    public ExternalAccountBinding(string keyId, byte[] hmacKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(hmacKey);

        KeyId = keyId;
        _hmacKey = (byte[])hmacKey.Clone();
    }

    /// <summary>Gets the key identifier issued by the certificate authority.</summary>
    public string KeyId { get; }

    internal byte[] GetHmacKey() => _hmacKey;

    private static byte[] DecodeKey(string hmacKey)
    {
        try
        {
            return Base64Url.Decode(hmacKey);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("The HMAC key is not valid base64url.", nameof(hmacKey), ex);
        }
    }
}
