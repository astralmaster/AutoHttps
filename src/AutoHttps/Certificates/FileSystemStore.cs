using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Certificates;

internal sealed class FileSystemStore : ICertificateStore, IAccountKeyStore
{
    private const string CertificateExtension = ".crt.pem";
    private const string PrivateKeyExtension = ".key.pem";
    private const string AccountKeyExtension = ".account.pem";
    private const int MoveAttempts = 5;

    private readonly string _root;

    public FileSystemStore(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        _root = Path.GetFullPath(root);
    }

    public string Root => _root;

    public async Task<CertificateMaterial?> LoadAsync(string name, CancellationToken cancellationToken)
    {
        string certificatePath = Path.Combine(_root, name + CertificateExtension);
        string keyPath = Path.Combine(_root, name + PrivateKeyExtension);

        if (!File.Exists(certificatePath) || !File.Exists(keyPath))
        {
            return null;
        }

        string chain = await File.ReadAllTextAsync(certificatePath, cancellationToken);
        string key = await File.ReadAllTextAsync(keyPath, cancellationToken);

        if (string.IsNullOrWhiteSpace(chain) || string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        return new CertificateMaterial(chain, key);
    }

    public async Task SaveAsync(string name, CertificateMaterial material, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(material);
        EnsureRoot();

        string certificatePath = Path.Combine(_root, name + CertificateExtension);
        string keyPath = Path.Combine(_root, name + PrivateKeyExtension);

        // Both halves are written to temporary files before either is published. Writing them one
        // after the other would leave a certificate with no key behind when the volume fills up
        // between the two, costing a duplicate certificate on the next start.
        string certificateStaged = await StageAsync(certificatePath, material.CertificateChainPem, cancellationToken);
        string keyStaged;

        try
        {
            keyStaged = await StageAsync(keyPath, material.PrivateKeyPem, cancellationToken);
        }
        catch
        {
            TryDelete(certificateStaged);
            throw;
        }

        // Kept so the pair can be put back together if the second move fails after the first succeeded:
        // a new key next to the old certificate matches neither, and the next start would discard both
        // and order again.
        string? previousKey = File.Exists(keyPath) ? await File.ReadAllTextAsync(keyPath, cancellationToken) : null;

        try
        {
            await MoveAsync(keyStaged, keyPath);
        }
        catch
        {
            TryDelete(keyStaged);
            TryDelete(certificateStaged);
            throw;
        }

        try
        {
            await MoveAsync(certificateStaged, certificatePath);
        }
        catch
        {
            TryDelete(certificateStaged);
            await RestoreAsync(keyPath, previousKey);
            throw;
        }
    }

    /// <summary>
    /// Publishes a staged file. On Windows a file cannot be replaced while any other handle has it
    /// open, whatever sharing that handle allows: a sibling instance reading the pair, an antivirus
    /// scanner or a backup agent. Each holds it only for a moment, so the failure is retried briefly
    /// before it counts.
    /// </summary>
    private static async Task MoveAsync(string staged, string destination)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                File.Move(staged, destination, overwrite: true);
                return;
            }
            catch (Exception ex) when (attempt < MoveAttempts - 1 && ex is IOException or UnauthorizedAccessException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(50 << attempt));
            }
        }
    }

    private static async Task RestoreAsync(string keyPath, string? previousKey)
    {
        try
        {
            if (previousKey is null)
            {
                TryDelete(keyPath);
                return;
            }

            string staged = await StageAsync(keyPath, previousKey, CancellationToken.None);
            try
            {
                await MoveAsync(staged, keyPath);
            }
            catch
            {
                TryDelete(staged);
                throw;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The original failure is the one worth reporting. This only tried to soften it.
        }
    }

    async Task<string?> IAccountKeyStore.LoadAsync(string name, CancellationToken cancellationToken)
    {
        string path = Path.Combine(_root, name + AccountKeyExtension);
        if (!File.Exists(path))
        {
            return null;
        }

        string key = await File.ReadAllTextAsync(path, cancellationToken);
        return string.IsNullOrWhiteSpace(key) ? null : key;
    }

    async Task IAccountKeyStore.SaveAsync(string name, string privateKeyPem, CancellationToken cancellationToken)
    {
        EnsureRoot();
        string path = Path.Combine(_root, name + AccountKeyExtension);
        await MoveAsync(await StageAsync(path, privateKeyPem, cancellationToken), path);
    }

    private void EnsureRoot() => CreatePrivateDirectory(_root);

    /// <summary>
    /// Creates the storage directory, readable only by the user this process runs as, unless it
    /// already exists. Every component that might be first to create it goes through here: whichever
    /// is first decides its permissions, and an existing directory is left as the operator set it.
    /// </summary>
    internal static void CreatePrivateDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);
        }
        else
        {
            Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    /// <summary>Writes the content to a temporary file next to its destination and returns that path.</summary>
    private static async Task<string> StageAsync(string path, string content, CancellationToken cancellationToken)
    {
        // A unique temporary name keeps two writers from corrupting each other's staging file, and
        // the move that publishes it is atomic, so a reader never sees a half written certificate.
        string temporary = path + "." + Guid.NewGuid().ToString("n")[..8] + ".tmp";

        // The file is created with its final permissions rather than changed afterwards: a key written
        // under the default mode and restricted only once the write finished is readable by any local
        // user for that moment, long enough for one watching the directory to open it.
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        try
        {
            await using (var stream = new FileStream(temporary, options))
            await using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
            {
                await writer.WriteAsync(content.AsMemory(), cancellationToken);
            }

            return temporary;
        }
        catch
        {
            TryDelete(temporary);
            throw;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
