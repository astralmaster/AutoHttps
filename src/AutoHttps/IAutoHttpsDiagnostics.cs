using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps;

/// <summary>
/// How a single diagnostic check turned out.
/// </summary>
public enum AutoHttpsCheckOutcome
{
    /// <summary>The check ran and found nothing wrong.</summary>
    Passed,

    /// <summary>The check could not run, usually because something it needs is not configured.</summary>
    Skipped,

    /// <summary>Something is worth looking at but may be deliberate.</summary>
    Warning,

    /// <summary>Something will stop a certificate being issued.</summary>
    Failed,
}

/// <summary>
/// One check from <see cref="IAutoHttpsDiagnostics"/>.
/// </summary>
public sealed class AutoHttpsCheck
{
    internal AutoHttpsCheck(string name, AutoHttpsCheckOutcome outcome, string detail, string? remedy = null)
    {
        Name = name;
        Outcome = outcome;
        Detail = detail;
        Remedy = remedy;
    }

    /// <summary>A short name for what was checked, for example <c>dns</c> or <c>port-80</c>.</summary>
    public string Name { get; }

    /// <summary>How the check turned out.</summary>
    public AutoHttpsCheckOutcome Outcome { get; }

    /// <summary>What was observed, including the evidence behind the outcome.</summary>
    public string Detail { get; }

    /// <summary>What to do about it, or <see langword="null"/> when there is nothing to do.</summary>
    public string? Remedy { get; }
}

/// <summary>
/// The result of running the diagnostics.
/// </summary>
public sealed class AutoHttpsDiagnosticsReport
{
    internal AutoHttpsDiagnosticsReport(IReadOnlyList<AutoHttpsCheck> checks)
    {
        Checks = checks;

        AutoHttpsCheckOutcome worst = AutoHttpsCheckOutcome.Passed;
        foreach (AutoHttpsCheck check in checks)
        {
            if (check.Outcome > worst)
            {
                worst = check.Outcome;
            }
        }

        Outcome = worst;
    }

    /// <summary>Every check that was run, in the order they ran.</summary>
    public IReadOnlyList<AutoHttpsCheck> Checks { get; }

    /// <summary>The worst outcome of any check.</summary>
    public AutoHttpsCheckOutcome Outcome { get; }

    /// <summary>
    /// The report as readable lines, one per check, which is the form to paste into an issue when
    /// asking for help.
    /// </summary>
    /// <returns>The formatted report.</returns>
    public override string ToString()
    {
        var text = new StringBuilder();
        text.Append("AutoHttps diagnostics: ").Append(Outcome).AppendLine();

        foreach (AutoHttpsCheck check in Checks)
        {
            text.Append("  [").Append(check.Outcome).Append("] ").Append(check.Name).Append(": ").Append(check.Detail);

            if (check.Remedy is { Length: > 0 } remedy)
            {
                text.AppendLine().Append("      ").Append(remedy);
            }

            text.AppendLine();
        }

        return text.ToString();
    }
}

/// <summary>
/// Checks the things that stop a certificate being issued, before or instead of waiting for an order to
/// fail: whether the name resolves, whether DNSSEC is intact, whether the authority is reachable,
/// whether anything is listening where the authority will connect, and whether the challenge path
/// actually reaches this application.
/// </summary>
/// <remarks>
/// Every check is read only. Resolve this from the service provider and call it from an endpoint or a
/// startup hook. AutoHttps also runs it once by itself after the first order failure unless
/// <see cref="AutoHttpsOptions.DiagnoseOrderFailures"/> is turned off.
/// </remarks>
public interface IAutoHttpsDiagnostics
{
    /// <summary>Runs every check.</summary>
    /// <param name="cancellationToken">A token that cancels the run.</param>
    /// <returns>The report.</returns>
    Task<AutoHttpsDiagnosticsReport> RunAsync(CancellationToken cancellationToken = default);
}
