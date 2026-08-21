using System;

namespace AutoHttps;

/// <summary>
/// A certificate chain and its private key, in PEM form.
/// </summary>
public sealed class CertificateMaterial
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateMaterial"/> class.
    /// </summary>
    /// <param name="certificateChainPem">The issued certificate followed by any intermediates, PEM encoded.</param>
    /// <param name="privateKeyPem">The PKCS#8 private key for the leaf certificate, PEM encoded.</param>
    public CertificateMaterial(string certificateChainPem, string privateKeyPem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateChainPem);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPem);

        CertificateChainPem = certificateChainPem;
        PrivateKeyPem = privateKeyPem;
    }

    /// <summary>Gets the issued certificate followed by any intermediates, PEM encoded.</summary>
    public string CertificateChainPem { get; }

    /// <summary>Gets the PKCS#8 private key for the leaf certificate, PEM encoded.</summary>
    public string PrivateKeyPem { get; }
}
