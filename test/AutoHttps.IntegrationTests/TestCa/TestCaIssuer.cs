using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AutoHttps.IntegrationTests.TestCa;

/// <summary>
/// A throwaway two level certificate authority: a self signed root that signs an intermediate,
/// which in turn signs the certificates the test authority issues.
/// </summary>
internal sealed class TestCaIssuer : IDisposable
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _intermediate;

    public TestCaIssuer(DateTimeOffset now)
    {
        // Every instance needs distinct subject names. Windows caches chain building by name, so
        // two authorities called the same thing but holding different keys make the chain engine
        // fail with "an unknown chain building error" once tests run side by side.
        string suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));

        _root = CreateAuthority($"AutoHttps Test Root {suffix}", issuer: null, now, TimeSpan.FromDays(3650));
        _intermediate = CreateAuthority($"AutoHttps Test Intermediate {suffix}", _root, now, TimeSpan.FromDays(1825));
    }

    public X509Certificate2 Root => _root;

    public X509Certificate2 Intermediate => _intermediate;

    public string IntermediatePem => _intermediate.ExportCertificatePem();

    public X509Certificate2 Issue(byte[] signingRequestDer, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        CertificateRequest request = CertificateRequest.LoadSigningRequest(
            signingRequestDer,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid(ServerAuthenticationOid)],
            critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
            _intermediate,
            includeKeyIdentifier: true,
            includeIssuerAndSerial: false));

        // A real authority signs with its own key whatever algorithm the subscriber chose. The
        // convenience overload of Create refuses to do that, so the generator is built explicitly.
        using ECDsa issuerKey = _intermediate.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("The test intermediate has no private key.");

        return request.Create(
            _intermediate.SubjectName,
            X509SignatureGenerator.CreateForECDsa(issuerKey),
            notBefore,
            notAfter,
            CreateSerialNumber());
    }

    public string BuildChainPem(X509Certificate2 leaf)
    {
        var builder = new StringBuilder();
        builder.Append(leaf.ExportCertificatePem()).Append('\n');
        builder.Append(IntermediatePem).Append('\n');
        return builder.ToString();
    }

    public IEnumerable<string> ReadSubjectAlternativeNames(byte[] signingRequestDer)
    {
        CertificateRequest request = CertificateRequest.LoadSigningRequest(
            signingRequestDer,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        foreach (X509Extension extension in request.CertificateExtensions)
        {
            if (extension.Oid?.Value != "2.5.29.17")
            {
                continue;
            }

            var subjectAlternativeName = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);

            foreach (string name in subjectAlternativeName.EnumerateDnsNames())
            {
                yield return name;
            }

            foreach (System.Net.IPAddress address in subjectAlternativeName.EnumerateIPAddresses())
            {
                yield return address.ToString();
            }
        }
    }

    public void Dispose()
    {
        _intermediate.Dispose();
        _root.Dispose();
    }

    private static X509Certificate2 CreateAuthority(string commonName, X509Certificate2? issuer, DateTimeOffset now, TimeSpan lifetime)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, hasPathLengthConstraint: false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        if (issuer is null)
        {
            return Persist(request.CreateSelfSigned(now.AddDays(-1), now + lifetime), key);
        }

        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
            issuer,
            includeKeyIdentifier: true,
            includeIssuerAndSerial: false));

        using X509Certificate2 signed = request.Create(issuer, now.AddDays(-1), now + lifetime, CreateSerialNumber());
        return Persist(signed, key);
    }

    private static X509Certificate2 Persist(X509Certificate2 certificate, ECDsa key)
    {
        using X509Certificate2 withKey = certificate.HasPrivateKey ? certificate : certificate.CopyWithPrivateKey(key);
        byte[] pkcs12 = withKey.Export(X509ContentType.Pkcs12);

        try
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12(pkcs12, null, X509KeyStorageFlags.Exportable);
#else
            return new X509Certificate2(pkcs12, (string?)null, X509KeyStorageFlags.Exportable);
#endif
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs12);
            certificate.Dispose();
        }
    }

    private static byte[] CreateSerialNumber()
    {
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;

        if (serial[0] == 0)
        {
            serial[0] = 1;
        }

        return serial;
    }
}
