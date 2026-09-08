using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps;

/// <summary>
/// Actions on the managed certificates that an application can trigger, such as revocation on a
/// suspected key compromise or when decommissioning a certificate. Inject it where you need it.
/// </summary>
public interface IAutoHttpsCertificateManager
{
    /// <summary>
    /// Revokes a certificate at the authority that issued it, signed with the ACME account key.
    /// </summary>
    /// <param name="certificate">The certificate to revoke.</param>
    /// <param name="reason">Why it is being revoked.</param>
    /// <param name="cancellationToken">A token to cancel the request.</param>
    Task RevokeAsync(
        X509Certificate2 certificate,
        RevocationReason reason = RevocationReason.Unspecified,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the certificate currently being served, if there is one.
    /// </summary>
    /// <returns><see langword="true"/> if a certificate was revoked, <see langword="false"/> if none is being served.</returns>
    Task<bool> RevokeCurrentAsync(
        RevocationReason reason = RevocationReason.Unspecified,
        CancellationToken cancellationToken = default);
}
