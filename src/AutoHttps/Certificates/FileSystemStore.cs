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

        try
        {
            File.Move(keyStaged, keyPath, overwrite: true);
            File.Move(certificateStaged, certificatePath, overwrite: true);
        }
        catch
        {
            TryDelete(keyStaged);
            TryDelete(certificateStaged);
            throw;
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
        File.Move(await StageAsync(path, privateKeyPem, cancellationToken), path, overwrite: true);
    }

    private void EnsureRoot()
    {
        if (Directory.Exists(_root))
        {
            return;
        }

        Directory.CreateDirectory(_root);
        RestrictDirectory(_root);
    }

    /// <summary>Writes the content to a temporary file next to its destination and returns that path.</summary>
    private static async Task<string> StageAsync(string path, string content, CancellationToken cancellationToken)
    {
        // A unique temporary name keeps two writers from corrupting each other's staging file, and
        // the move that publishes it is atomic, so a reader never sees a half written certificate.
        string temporary = path + "." + Guid.NewGuid().ToString("n")[..8] + ".tmp";

        try
        {
            await File.WriteAllTextAsync(temporary, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken);
            RestrictFile(temporary);

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

    private static void RestrictDirectory(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void RestrictFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
