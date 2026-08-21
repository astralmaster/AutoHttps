using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AutoHttps.Internal;

namespace AutoHttps.Acme;

internal sealed class AcmeKey : IDisposable
{
    private readonly ECDsa? _ecdsa;
    private readonly RSA? _rsa;
    private readonly HashAlgorithmName _hash;

    private AcmeKey(ECDsa ecdsa)
    {
        _ecdsa = ecdsa;
        (SignatureAlgorithm, _hash) = ecdsa.KeySize switch
        {
            256 => ("ES256", HashAlgorithmName.SHA256),
            384 => ("ES384", HashAlgorithmName.SHA384),
            521 => ("ES512", HashAlgorithmName.SHA512),
            _ => throw new NotSupportedException(
                string.Create(CultureInfo.InvariantCulture, $"Unsupported EC key size {ecdsa.KeySize}.")),
        };

        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        string curve = ecdsa.KeySize switch
        {
            256 => "P-256",
            384 => "P-384",
            _ => "P-521",
        };

        Jwk = $"{{\"crv\":\"{curve}\",\"kty\":\"EC\",\"x\":\"{Base64Url.Encode(parameters.Q.X!)}\",\"y\":\"{Base64Url.Encode(parameters.Q.Y!)}\"}}";
        Thumbprint = ComputeThumbprint(Jwk);
    }

    private AcmeKey(RSA rsa)
    {
        _rsa = rsa;
        SignatureAlgorithm = "RS256";
        _hash = HashAlgorithmName.SHA256;

        RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: false);
        Jwk = $"{{\"e\":\"{Base64Url.Encode(parameters.Exponent!)}\",\"kty\":\"RSA\",\"n\":\"{Base64Url.Encode(parameters.Modulus!)}\"}}";
        Thumbprint = ComputeThumbprint(Jwk);
    }

    public string SignatureAlgorithm { get; }

    public string Jwk { get; }

    public string Thumbprint { get; }

    public static AcmeKey CreateEcdsa(int keySize = 256) => new(ECDsa.Create(keySize switch
    {
        256 => ECCurve.NamedCurves.nistP256,
        384 => ECCurve.NamedCurves.nistP384,
        521 => ECCurve.NamedCurves.nistP521,
        _ => throw new ArgumentOutOfRangeException(nameof(keySize)),
    }));

    public static AcmeKey CreateRsa(int keySize = 2048)
    {
        if (keySize < 2048)
        {
            throw new ArgumentOutOfRangeException(nameof(keySize), "RSA keys must be at least 2048 bits.");
        }

        return new AcmeKey(RSA.Create(keySize));
    }

    public static AcmeKey ImportPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);

        ECDsa ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(pem);
            return new AcmeKey(ecdsa);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            ecdsa.Dispose();
        }

        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return new AcmeKey(rsa);
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

    public byte[] Sign(ReadOnlySpan<byte> data) => _ecdsa is not null
        ? _ecdsa.SignData(data, _hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
        : _rsa!.SignData(data.ToArray(), _hash, RSASignaturePadding.Pkcs1);

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => _ecdsa is not null
        ? _ecdsa.VerifyData(data, signature, _hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
        : _rsa!.VerifyData(data.ToArray(), signature.ToArray(), _hash, RSASignaturePadding.Pkcs1);

    public string GetKeyAuthorization(string token) => token + "." + Thumbprint;

    public string GetDnsRecordValue(string token)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(GetKeyAuthorization(token)));
        return Base64Url.Encode(digest);
    }

    public void Dispose()
    {
        _ecdsa?.Dispose();
        _rsa?.Dispose();
    }

    internal static string ComputeThumbprint(string canonicalJwk) =>
        Base64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJwk)));
}
