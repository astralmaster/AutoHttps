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

    public string ExportPem() => _ecdsa is not null
        ? _ecdsa.ExportPkcs8PrivateKeyPem()
        : _rsa!.ExportPkcs8PrivateKeyPem();

    public CertificateRequest CreateRequest(X500DistinguishedName subject) => _ecdsa is not null
        ? new CertificateRequest(subject, _ecdsa, HashAlgorithmName.SHA256)
        : new CertificateRequest(subject, _rsa!, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public void Dispose()
    {
        _ecdsa?.Dispose();
        _rsa?.Dispose();
    }
}
