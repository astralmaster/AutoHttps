namespace AutoHttps;

/// <summary>
/// The key algorithm used for issued certificates.
/// </summary>
public enum KeyAlgorithm
{
    /// <summary>ECDSA on the NIST P-256 curve. The default, and the smallest and fastest option.</summary>
    EcdsaP256,

    /// <summary>ECDSA on the NIST P-384 curve.</summary>
    EcdsaP384,

    /// <summary>2048-bit RSA. Use when clients cannot negotiate ECDSA cipher suites.</summary>
    Rsa2048,

    /// <summary>3072-bit RSA.</summary>
    Rsa3072,

    /// <summary>4096-bit RSA.</summary>
    Rsa4096,
}
