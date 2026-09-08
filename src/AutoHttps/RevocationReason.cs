namespace AutoHttps;

/// <summary>
/// Why a certificate is being revoked, as an RFC 5280 CRL reason code. Only the reasons an ACME
/// authority accepts from a subscriber are listed.
/// </summary>
public enum RevocationReason
{
    /// <summary>No specific reason is given.</summary>
    Unspecified = 0,

    /// <summary>The certificate's private key may have been exposed.</summary>
    KeyCompromise = 1,

    /// <summary>The subject's affiliation has changed.</summary>
    AffiliationChanged = 3,

    /// <summary>The certificate has been replaced by another.</summary>
    Superseded = 4,

    /// <summary>The certificate is no longer needed for the purpose it was issued for.</summary>
    CessationOfOperation = 5,
}
