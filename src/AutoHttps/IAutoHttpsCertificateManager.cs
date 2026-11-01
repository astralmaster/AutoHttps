using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps;

/// <summary>
/// Actions on the managed certificates that an application can trigger, such as replacing and
/// revoking a certificate on a suspected key compromise, or revoking one when decommissioning it.
/// Inject it where you need it.
/// </summary>
public interface IAutoHttpsCertificateManager
{
    /// <summary>
    /// Replaces the certificate being served with a new one now, whatever the renewal schedule says,
    /// and returns once the new certificate is in use. Use it after a key may have leaked, or to apply
    /// a changed <see cref="AutoHttpsOptions.Profile"/> without waiting for the next renewal.
    /// </summary>
    /// <param name="revokePrevious">
    /// When set, the certificate that was replaced is revoked for this reason once the new one is in
    /// use. Pass <see cref="RevocationReason.KeyCompromise"/> after a key may have leaked. Nothing is
    /// revoked when no certificate was being served.
    /// </param>
    /// <param name="cancellationToken">Stops waiting. An order already under way carries on.</param>
    /// <returns>A task that completes once a new certificate is served, and the old one revoked if asked.</returns>
    /// <remarks>
    /// The order goes to the certificate authority like any other and counts against its limits. Let's
    /// Encrypt allows 5 certificates for the same names a week. If the order fails, the task fails with
    /// the order's exception, an <see cref="AcmeRateLimitException"/> while the authority has asked to
    /// wait, and the certificate in use stays until its ordinary renewal. Several calls made together
    /// share one order. Instances that share the certificate store pick the new certificate up at their
    /// next check, within <see cref="AutoHttpsOptions.RenewalCheckInterval"/>.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// AutoHttps orders nothing in this process, because a development certificate is being served.
    /// </exception>
    Task RenewAsync(RevocationReason? revokePrevious = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException($"This {nameof(IAutoHttpsCertificateManager)} does not implement {nameof(RenewAsync)}.");

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
