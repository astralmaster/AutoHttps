using System;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps;

/// <summary>
/// Publishes and removes the DNS TXT records that satisfy an ACME <c>dns-01</c> challenge.
/// Required for wildcard certificates, which no other challenge type can validate.
/// </summary>
public interface IDnsChallengeProvider
{
    /// <summary>Creates a TXT record.</summary>
    /// <param name="recordName">The fully qualified record name, for example <c>_acme-challenge.example.com</c>.</param>
    /// <param name="recordValue">The record value the certificate authority expects to read.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <remarks>
    /// A domain may need more than one record at a time. Add records rather than replacing the record set.
    /// </remarks>
    Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken);

    /// <summary>Removes a TXT record created by <see cref="CreateTxtRecordAsync"/>.</summary>
    /// <param name="recordName">The fully qualified record name.</param>
    /// <param name="recordValue">The record value to remove.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <remarks>
    /// This may be called for a record that was never created, because creation can fail partway.
    /// Removing a record that is not there should succeed rather than throw.
    /// </remarks>
    Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken);
}

/// <summary>
/// An <see cref="IDnsChallengeProvider"/> built from two callbacks.
/// </summary>
public sealed class DelegateDnsChallengeProvider : IDnsChallengeProvider
{
    private readonly Func<string, string, CancellationToken, Task> _create;
    private readonly Func<string, string, CancellationToken, Task> _delete;

    /// <summary>
    /// Initializes a new instance of the <see cref="DelegateDnsChallengeProvider"/> class.
    /// </summary>
    /// <param name="create">Creates a TXT record.</param>
    /// <param name="delete">Removes a TXT record.</param>
    public DelegateDnsChallengeProvider(
        Func<string, string, CancellationToken, Task> create,
        Func<string, string, CancellationToken, Task> delete)
    {
        ArgumentNullException.ThrowIfNull(create);
        ArgumentNullException.ThrowIfNull(delete);

        _create = create;
        _delete = delete;
    }

    /// <inheritdoc />
    public Task CreateTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
        _create(recordName, recordValue, cancellationToken);

    /// <inheritdoc />
    public Task DeleteTxtRecordAsync(string recordName, string recordValue, CancellationToken cancellationToken) =>
        _delete(recordName, recordValue, cancellationToken);
}
