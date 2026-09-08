using System;
using System.Security.Cryptography;
using System.Text;

namespace AutoHttps.Azure;

/// <summary>
/// Builds Key Vault secret names from the store identifiers AutoHttps uses. Those identifiers contain
/// dots and underscores, which Key Vault does not allow, so each is turned into a name of letters,
/// digits and hyphens, with a hash of the original so distinct identifiers never collide.
/// </summary>
internal static class KeyVaultSecretNames
{
    private const int MaxBodyLength = 80;

    public static string For(string prefix, string kind, string identifier)
    {
        string body = Sanitize(identifier);
        if (body.Length > MaxBodyLength)
        {
            body = body[..MaxBodyLength];
        }

        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identifier)))[..8].ToLowerInvariant();
        return prefix + kind + "-" + body + "-" + hash;
    }

    private static string Sanitize(string identifier)
    {
        var builder = new StringBuilder(identifier.Length);
        foreach (char character in identifier)
        {
            builder.Append(char.IsAsciiLetterOrDigit(character) || character == '-' ? character : '-');
        }

        return builder.ToString();
    }
}
