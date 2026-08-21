using System;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Internal;

namespace AutoHttps.Acme;

/// <summary>
/// Computes the certificate identifier used by ACME Renewal Information (RFC 9773).
/// </summary>
internal static class AcmeCertificateId
{
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";

    public static bool TryCompute(X509Certificate2 certificate, out string certificateId)
    {
        certificateId = string.Empty;

        X509Extension? extension = certificate.Extensions[AuthorityKeyIdentifierOid];
        if (extension is null)
        {
            return false;
        }

        ReadOnlyMemory<byte>? keyIdentifier;
        try
        {
            var authorityKeyIdentifier = new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical);
            keyIdentifier = authorityKeyIdentifier.KeyIdentifier;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return false;
        }

        if (keyIdentifier is not { } identifier || identifier.IsEmpty)
        {
            return false;
        }

        // RFC 9773 asks for the content octets of the serialNumber field, which is exactly what
        // SerialNumberBytes exposes in big-endian order.
        certificateId = Base64Url.Encode(identifier.Span) + "." + Base64Url.Encode(certificate.SerialNumberBytes.Span);
        return true;
    }
}
