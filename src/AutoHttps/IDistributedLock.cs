using System;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps;

/// <summary>
/// Stops several instances of an application from ordering the same certificate at the same time.
/// </summary>
/// <remarks>
/// The default implementation uses a lock file in the storage directory, which is correct for a
/// single instance and for several instances sharing a volume. Replace it when instances do not
/// share a filesystem.
/// </remarks>
public interface IDistributedLock
{
    /// <summary>Attempts to take the lock without waiting.</summary>
    /// <param name="name">A stable identifier for the resource being protected.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <returns>
    /// A handle that releases the lock when disposed, or <see langword="null"/> if another holder
    /// currently owns it.
    /// </returns>
    Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken);
}
