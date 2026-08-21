using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Internal;

namespace AutoHttps.Certificates;

internal static class CertificateFactory
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
    private const int MaxCommonNameLength = 64;

    // Schannel rejects ephemeral keys for server authentication, so on Windows the key has to be
    // persisted for the lifetime of the certificate object. Everywhere else an ephemeral key
    // avoids writing key material to disk.
    private static readonly X509KeyStorageFlags StorageFlags = OperatingSystem.IsWindows()
        ? X509KeyStorageFlags.Exportable
        : X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

    public static byte[] CreateSigningRequest(IReadOnlyList<string> identifiers, CertificateKey key)
    {
        if (identifiers.Count == 0)
        {
            throw new ArgumentException("At least one identifier is required.", nameof(identifiers));
        }

        CertificateRequest request = key.CreateRequest(BuildSubject(identifiers[0]));
        request.CertificateExtensions.Add(BuildSubjectAlternativeNames(identifiers));

        return request.CreateSigningRequest();
    }

    public static ServerCertificate CreateFromPem(string certificateChainPem, string privateKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateChainPem);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPem);

        var chain = new X509Certificate2Collection();
        chain.ImportFromPem(certificateChainPem);

        if (chain.Count == 0)
        {
            throw new AcmeException("The certificate authority returned a response that contained no certificates.");
        }

        var intermediates = new X509Certificate2Collection();
        X509Certificate2 leaf = chain[0];

        try
        {
            for (int i = 1; i < chain.Count; i++)
            {
                intermediates.Add(chain[i]);
            }

            X509Certificate2 usable = AttachPrivateKey(leaf.ExportCertificatePem(), privateKeyPem);
            return new ServerCertificate(usable, intermediates);
        }
        catch
        {
            foreach (X509Certificate2 intermediate in intermediates)
            {
                intermediate.Dispose();
            }

            throw;
        }
        finally
        {
            leaf.Dispose();
        }
    }

    /// <summary>
    /// Builds the placeholder served before a real certificate arrives. It covers every configured
    /// name: a placeholder that named only the first would add a name mismatch to the certificate
    /// warning clients already see, for every other domain.
    /// </summary>
    public static X509Certificate2 CreateSelfSigned(IReadOnlyList<string> subjectNames, DateTimeOffset now, TimeSpan lifetime)
    {
        if (subjectNames.Count == 0)
        {
            throw new ArgumentException("At least one name is required.", nameof(subjectNames));
        }

        using var key = CertificateKey.Create(KeyAlgorithm.EcdsaP256);
        CertificateRequest request = key.CreateRequest(BuildSubject(subjectNames[0]));

        request.CertificateExtensions.Add(BuildSubjectAlternativeNames(subjectNames));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid(ServerAuthenticationOid)],
            critical: false));

        using X509Certificate2 selfSigned = request.CreateSelfSigned(now.AddMinutes(-5), now + lifetime);
        return Reload(selfSigned);
    }

    private static X509Certificate2 AttachPrivateKey(string certificatePem, string privateKeyPem)
    {
        using X509Certificate2 combined = X509Certificate2.CreateFromPem(certificatePem, privateKeyPem);
        return Reload(combined);
    }

    private static X509Certificate2 Reload(X509Certificate2 certificate)
    {
        byte[] pkcs12 = certificate.Export(X509ContentType.Pkcs12);
        try
        {
            return CertificateLoader.LoadPkcs12(pkcs12, password: null, StorageFlags);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs12);
        }
    }

    private static X500DistinguishedName BuildSubject(string identifier)
    {
        if (identifier.Length > MaxCommonNameLength)
        {
            return new X500DistinguishedName(string.Empty);
        }

        return new X500DistinguishedName($"CN={identifier}");
    }

    private static X509Extension BuildSubjectAlternativeNames(IReadOnlyList<string> identifiers)
    {
        var builder = new SubjectAlternativeNameBuilder();

        foreach (string identifier in identifiers)
        {
            if (IPAddress.TryParse(identifier, out IPAddress? address))
            {
                builder.AddIpAddress(address);
            }
            else
            {
                builder.AddDnsName(identifier);
            }
        }

        return builder.Build();
    }
}
