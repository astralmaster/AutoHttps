using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AutoHttps.Renewal;

internal static class RenewalCalculator
{
    public static DateTimeOffset ComputeRenewalTime(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        RenewalWindow? suggestedWindow,
        ReadOnlySpan<byte> serialNumber,
        double threshold,
        DateTimeOffset now)
    {
        if (notAfter <= notBefore)
        {
            return now;
        }

        DateTimeOffset renewAt = suggestedWindow is { } window && window.End > window.Start
            ? PickWithinWindow(window, serialNumber)
            : notAfter - ((notAfter - notBefore) * threshold);

        if (renewAt > notAfter)
        {
            renewAt = notAfter;
        }

        return renewAt < now ? now : renewAt;
    }

    private static DateTimeOffset PickWithinWindow(RenewalWindow window, ReadOnlySpan<byte> serialNumber)
    {
        // RFC 9773 asks clients to pick a uniformly random point in the window so that a certificate
        // authority is not hit by every subscriber at once. Deriving it from the serial number keeps
        // the choice stable across restarts, so a process that restarts often does not renew early.
        double fraction = DeriveFraction(serialNumber, window.Start);
        return window.Start + ((window.End - window.Start) * fraction);
    }

    private static double DeriveFraction(ReadOnlySpan<byte> serialNumber, DateTimeOffset windowStart)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(buffer, windowStart.UtcTicks);

        Span<byte> digest = stackalloc byte[32];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(serialNumber);
        hash.AppendData(buffer);
        hash.GetHashAndReset(digest);

        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(digest);
        return value / (double)ulong.MaxValue;
    }
}

internal readonly record struct RenewalWindow(DateTimeOffset Start, DateTimeOffset End);
