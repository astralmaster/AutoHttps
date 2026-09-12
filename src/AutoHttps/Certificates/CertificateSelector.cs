using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using AutoHttps.Internal;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

namespace AutoHttps.Certificates;

internal sealed class CertificateSelector : IDisposable
{
    private static readonly TimeSpan RetirementDelay = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FallbackLifetime = TimeSpan.FromDays(14);

    private readonly ILogger<CertificateSelector> _logger;
    private readonly TimeProvider _time;
    private readonly ConcurrentQueue<RetiredCertificate> _retired = new();

    private ServerCertificate[] _certificates = [];
    private X509Certificate2? _fallback;
    private string[] _fallbackNames = [];
    private int _fallbackReported;
    private int _chainWarningReported;

    public CertificateSelector(ILogger<CertificateSelector> logger, TimeProvider time)
    {
        _logger = logger;
        _time = time;
    }

    /// <summary>
    /// The certificate selector Kestrel calls. This path can only hand back the leaf: Kestrel drops
    /// a configured chain as soon as a selector is in use, so anything the authority issued
    /// alongside the leaf is lost here.
    /// </summary>
    public X509Certificate2? Select(ConnectionContext? connection, string? hostName)
    {
        if (Find(hostName) is not { } certificate)
        {
            return SelectFallback(hostName);
        }

        if (certificate.Intermediates.Count > 0 && Interlocked.Exchange(ref _chainWarningReported, 1) == 0)
        {
            Log.IncompleteChainServed(_logger, hostName ?? certificate.SubjectNames[0], certificate.Intermediates.Count);
        }

        return certificate.Leaf;
    }

    public ServerCertificate? Find(string? hostName)
    {
        ServerCertificate[] certificates = Volatile.Read(ref _certificates);

        if (certificates.Length == 0)
        {
            return null;
        }

        if (string.IsNullOrEmpty(hostName))
        {
            return certificates[0];
        }

        foreach (ServerCertificate certificate in certificates)
        {
            if (certificate.Matches(hostName))
            {
                return certificate;
            }
        }

        return null;
    }

    public void Publish(ServerCertificate certificate)
    {
        while (true)
        {
            ServerCertificate[] current = Volatile.Read(ref _certificates);
            var replaced = new List<ServerCertificate>();
            var next = new List<ServerCertificate>(current.Length + 1) { certificate };

            foreach (ServerCertificate existing in current)
            {
                if (Overlaps(existing, certificate))
                {
                    replaced.Add(existing);
                }
                else
                {
                    next.Add(existing);
                }
            }

            if (Interlocked.CompareExchange(ref _certificates, next.ToArray(), current) == current)
            {
                Interlocked.Exchange(ref _fallbackReported, 0);
                DateTimeOffset retireAt = _time.GetUtcNow() + RetirementDelay;
                foreach (ServerCertificate old in replaced)
                {
                    _retired.Enqueue(new RetiredCertificate(old, retireAt));
                }

                return;
            }
        }
    }

    public void SetFallbackNames(IReadOnlyList<string> names) => _fallbackNames = [.. names];

    internal int RetiredCount => _retired.Count;

    public void CollectRetired()
    {
        DateTimeOffset now = _time.GetUtcNow();

        while (_retired.TryPeek(out RetiredCertificate? candidate) && candidate.RetireAt <= now)
        {
            if (_retired.TryDequeue(out RetiredCertificate? retired))
            {
                retired.Certificate.Dispose();
            }
        }
    }

    public void Dispose()
    {
        foreach (ServerCertificate certificate in Volatile.Read(ref _certificates))
        {
            certificate.Dispose();
        }

        while (_retired.TryDequeue(out RetiredCertificate? retired))
        {
            retired.Certificate.Dispose();
        }

        _fallback?.Dispose();
    }

    private X509Certificate2? SelectFallback(string? hostName)
    {
        string[] names = _fallbackNames;
        if (names.Length == 0)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(hostName) && !IsConfigured(names, hostName))
        {
            return null;
        }

        X509Certificate2 fallback = EnsureFallback(names);

        // Reported once per outage rather than once per handshake, which would flood the log of a
        // server that is taking connections while its first certificate is still being issued.
        if (Interlocked.Exchange(ref _fallbackReported, 1) == 0)
        {
            Log.FallbackCertificateServed(_logger, hostName ?? names[0]);
        }

        return fallback;
    }

    // The fallback is self-signed and lives for FallbackLifetime. If the first real certificate has
    // still not arrived by the time it expires, generate a fresh one rather than keep serving an
    // expired certificate for the rest of the outage. The old one is retired on the same delay as a
    // replaced certificate, because a handshake in flight may still hold it.
    private X509Certificate2 EnsureFallback(string[] names)
    {
        while (true)
        {
            DateTimeOffset now = _time.GetUtcNow();
            X509Certificate2? current = Volatile.Read(ref _fallback);

            if (current is not null && new DateTimeOffset(current.NotAfter.ToUniversalTime(), TimeSpan.Zero) > now)
            {
                return current;
            }

            X509Certificate2 created = CertificateFactory.CreateSelfSigned(names, now, FallbackLifetime);
            if (Interlocked.CompareExchange(ref _fallback, created, current) == current)
            {
                if (current is not null)
                {
                    _retired.Enqueue(new RetiredCertificate(current, now + RetirementDelay));
                }

                return created;
            }

            // Another handshake generated one first; keep theirs and drop this attempt.
            created.Dispose();
        }
    }

    private static bool IsConfigured(string[] names, string hostName)
    {
        foreach (string name in names)
        {
            if (HostNameMatcher.Matches(name, hostName))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Overlaps(ServerCertificate left, ServerCertificate right)
    {
        foreach (string name in right.SubjectNames)
        {
            foreach (string existing in left.SubjectNames)
            {
                if (string.Equals(existing, name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    // Holds either a replaced ServerCertificate or a superseded self-signed fallback, both of which
    // are disposed once no handshake can still be holding them.
    private sealed record RetiredCertificate(IDisposable Certificate, DateTimeOffset RetireAt);
}
