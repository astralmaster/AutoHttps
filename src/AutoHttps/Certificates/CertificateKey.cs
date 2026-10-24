using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AutoHttps.Certificates;

internal sealed class CertificateKey : IDisposable
{
    private readonly ECDsa? _ecdsa;
    private readonly RSA? _rsa;

    private CertificateKey(ECDsa ecdsa) => _ecdsa = ecdsa;

    private CertificateKey(RSA rsa) => _rsa = rsa;

    public static CertificateKey Create(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.EcdsaP256 => new CertificateKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)),
        KeyAlgorithm.EcdsaP384 => new CertificateKey(ECDsa.Create(ECCurve.NamedCurves.nistP384)),
        KeyAlgorithm.Rsa2048 => new CertificateKey(RSA.Create(2048)),
        KeyAlgorithm.Rsa3072 => new CertificateKey(RSA.Create(3072)),
        KeyAlgorithm.Rsa4096 => new CertificateKey(RSA.Create(4096)),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    public static CertificateKey ImportPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);

        ECDsa ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(pem);
            return new CertificateKey(ecdsa);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            ecdsa.Dispose();
        }

        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return new CertificateKey(rsa);
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>Whether the certificate's public key is of the kind and size <paramref name="algorithm"/> creates.</summary>
    public static bool Matches(X509Certificate2 certificate, KeyAlgorithm algorithm)
    {
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            return algorithm switch
            {
                KeyAlgorithm.EcdsaP256 => ecdsa.KeySize == 256,
                KeyAlgorithm.EcdsaP384 => ecdsa.KeySize == 384,
                _ => false,
            };
        }

        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            return algorithm switch
            {
                KeyAlgorithm.Rsa2048 => rsa.KeySize == 2048,
                KeyAlgorithm.Rsa3072 => rsa.KeySize == 3072,
                KeyAlgorithm.Rsa4096 => rsa.KeySize == 4096,
                _ => false,
            };
        }

        // A key of some other kind was not ordered by this library, so there is nothing to compare.
        return true;
    }

    public string ExportPem() => _ecdsa is not null
        ? _ecdsa.ExportPkcs8PrivateKeyPem()
        : _rsa!.ExportPkcs8PrivateKeyPem();

    // A P-384 key is signed with SHA-384, the pairing the curve is meant for. AWS Certificate Manager
    // refuses a P-384 request signed with SHA-256 ("EC P-384 key requires signing algorithm
    // SHA384withECDSA"), and others accept either.
    public CertificateRequest CreateRequest(X500DistinguishedName subject) => _ecdsa is not null
        ? new CertificateRequest(subject, _ecdsa, _ecdsa.KeySize >= 384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256)
        : new CertificateRequest(subject, _rsa!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public void Dispose()
    {
        _ecdsa?.Dispose();
        _rsa?.Dispose();
    }
}
