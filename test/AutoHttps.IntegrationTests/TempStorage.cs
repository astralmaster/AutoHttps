using System;
using System.IO;

namespace AutoHttps.IntegrationTests;

/// <summary>A per-test storage directory, so tests never touch the machine's real certificate store.</summary>
internal sealed class TempStorage : IDisposable
{
    public TempStorage()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "autohttps-it", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
