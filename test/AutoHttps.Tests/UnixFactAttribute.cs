using System;
using Xunit;

namespace AutoHttps.Tests;

/// <summary>
/// A test about Unix file modes. On Windows it is reported as skipped rather than returning early and
/// reporting a pass it never earned. It runs for real on Linux and macOS, including in CI.
/// </summary>
public sealed class UnixFactAttribute : FactAttribute
{
    public UnixFactAttribute()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip = "Unix file modes do not exist on Windows.";
        }
    }
}
