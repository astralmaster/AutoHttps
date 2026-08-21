using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AutoHttps.Certificates;

internal sealed class ServerCertificate : IDisposable
{
    private readonly SslStreamCertificateContext? _context;

    public ServerCertificate(X509Certificate2 leaf, X509Certificate2Collection intermediates)
    {
        Leaf = leaf;
        Intermediates = intermediates;
        SubjectNames = ReadSubjectNames(leaf);

        try
        {
            _context = SslStreamCertificateContext.Create(leaf, intermediates, offline: true);
        }
        catch (CryptographicException)
        {
            _context = null;
        }
        catch (AuthenticationException)
        {
            _context = null;
        }
    }

    public X509Certificate2 Leaf { get; }

    public X509Certificate2Collection Intermediates { get; }

    public IReadOnlyList<string> SubjectNames { get; }

    public DateTimeOffset NotAfter => new(Leaf.NotAfter.ToUniversalTime(), TimeSpan.Zero);

    public DateTimeOffset NotBefore => new(Leaf.NotBefore.ToUniversalTime(), TimeSpan.Zero);

    public SslStreamCertificateContext? Context => _context;

    public bool Matches(string name)
    {
        foreach (string subjectName in SubjectNames)
        {
            if (HostNameMatcher.Matches(subjectName, name))
            {
                return true;
            }
        }

        return false;
    }

    public void Dispose()
    {
        Leaf.Dispose();
        foreach (X509Certificate2 intermediate in Intermediates)
        {
            intermediate.Dispose();
        }
    }

    private static List<string> ReadSubjectNames(X509Certificate2 certificate)
    {
        var names = new List<string>();

        X509Extension? extension = certificate.Extensions["2.5.29.17"];
        if (extension is not null)
        {
            try
            {
                var subjectAlternativeName = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
                names.AddRange(subjectAlternativeName.EnumerateDnsNames());

                foreach (System.Net.IPAddress address in subjectAlternativeName.EnumerateIPAddresses())
                {
                    names.Add(address.ToString());
                }
            }
            catch (CryptographicException)
            {
                names.Clear();
            }
        }

        if (names.Count == 0)
        {
            string common = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (!string.IsNullOrEmpty(common))
            {
                names.Add(common);
            }
        }

        return names;
    }
}
