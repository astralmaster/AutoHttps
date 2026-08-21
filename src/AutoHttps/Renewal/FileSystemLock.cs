using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Renewal;

internal sealed class FileSystemLock : IDistributedLock
{
    private readonly string _root;

    public FileSystemLock(string root) => _root = root;

    public Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken)
    {
        EnsureDirectory();
        string path = Path.Combine(_root, name + ".lock");

        try
        {
            var stream = new FileStream(
                path,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.DeleteOnClose);

            return Task.FromResult<IAsyncDisposable?>(new Handle(stream));
        }
        catch (IOException) when (IsWritable())
        {
            // Only a directory this process can otherwise write to proves the lock is genuinely
            // held elsewhere. Without that check an unwritable volume looks identical to a busy
            // sibling, and the application waits forever for an instance that does not exist.
            return Task.FromResult<IAsyncDisposable?>(null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw NotWritable(ex);
        }
    }

    private void EnsureDirectory()
    {
        try
        {
            if (!Directory.Exists(_root))
            {
                Directory.CreateDirectory(_root);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw NotWritable(ex);
        }
    }

    private InvalidOperationException NotWritable(Exception cause) =>
        new($"The AutoHttps storage directory '{_root}' cannot be written to, so no certificate can be " +
            $"obtained or kept. Check that the volume is not mounted read only and that the user this " +
            $"process runs as owns the directory. The underlying error was: {cause.Message}",
            cause);

    private bool IsWritable()
    {
        string probe = Path.Combine(_root, ".autohttps-write-probe-" + Guid.NewGuid().ToString("n")[..8]);

        try
        {
            using (File.Create(probe, bufferSize: 1, FileOptions.DeleteOnClose))
            {
                return true;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private sealed class Handle : IAsyncDisposable
    {
        private readonly FileStream _stream;

        public Handle(FileStream stream) => _stream = stream;

        public ValueTask DisposeAsync() => _stream.DisposeAsync();
    }
}

internal sealed class NullDistributedLock : IDistributedLock
{
    private static readonly Task<IAsyncDisposable?> Acquired = Task.FromResult<IAsyncDisposable?>(new Handle());

    public Task<IAsyncDisposable?> TryAcquireAsync(string name, CancellationToken cancellationToken) => Acquired;

    private sealed class Handle : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
