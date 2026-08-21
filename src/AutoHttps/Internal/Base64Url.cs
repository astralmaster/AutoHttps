using System;
using System.Buffers;

namespace AutoHttps.Internal;

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return string.Empty;
        }

        int maxChars = ((bytes.Length + 2) / 3) * 4;
        char[]? rented = null;
        Span<char> buffer = maxChars <= 256
            ? stackalloc char[256]
            : (rented = ArrayPool<char>.Shared.Rent(maxChars));

        try
        {
            if (!Convert.TryToBase64Chars(bytes, buffer, out int written))
            {
                throw new InvalidOperationException("Base64 conversion buffer was too small.");
            }

            Span<char> chars = buffer[..written];
            while (!chars.IsEmpty && chars[^1] == '=')
            {
                chars = chars[..^1];
            }

            for (int i = 0; i < chars.Length; i++)
            {
                chars[i] = chars[i] switch
                {
                    '+' => '-',
                    '/' => '_',
                    var c => c,
                };
            }

            return new string(chars);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<char>.Shared.Return(rented);
            }
        }
    }

    public static byte[] Decode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        int padding = (4 - (value.Length % 4)) % 4;
        if (padding == 3)
        {
            throw new FormatException("Value is not valid base64url.");
        }

        char[] buffer = new char[value.Length + padding];
        for (int i = 0; i < value.Length; i++)
        {
            buffer[i] = value[i] switch
            {
                '-' => '+',
                '_' => '/',
                var c => c,
            };
        }

        buffer.AsSpan(value.Length).Fill('=');
        return Convert.FromBase64CharArray(buffer, 0, buffer.Length);
    }
}
