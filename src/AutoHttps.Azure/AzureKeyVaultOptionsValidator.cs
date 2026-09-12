using System.Collections.Generic;
using Microsoft.Extensions.Options;

namespace AutoHttps.Azure;

/// <summary>
/// Validates <see cref="AzureKeyVaultOptions"/> at startup, so a prefix Key Vault would reject is
/// reported by name rather than surfacing later as a raw SDK error the first time a certificate is
/// written.
/// </summary>
internal sealed class AzureKeyVaultOptionsValidator : IValidateOptions<AzureKeyVaultOptions>
{
    // A Key Vault secret name is at most 127 characters of letters, digits and hyphens. The composed
    // name is prefix + kind + "-" + body + "-" + hash, where the longest kind is "account" (7), the
    // body is capped at 80 and the hash is 8, which leaves 30 characters for the prefix.
    internal const int MaxPrefixLength = 30;

    public ValidateOptionsResult Validate(string? name, AzureKeyVaultOptions options)
    {
        var failures = new List<string>();

        if (options.VaultUri is null)
        {
            failures.Add("AzureKeyVaultOptions.VaultUri is required.");
        }

        string prefix = options.SecretPrefix ?? string.Empty;

        if (prefix.Length > MaxPrefixLength)
        {
            failures.Add(
                $"AzureKeyVaultOptions.SecretPrefix must be at most {MaxPrefixLength} characters so the " +
                $"Key Vault secret name stays within 127; '{prefix}' is {prefix.Length}.");
        }

        foreach (char character in prefix)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character != '-')
            {
                failures.Add(
                    "AzureKeyVaultOptions.SecretPrefix may contain only letters, digits and hyphens; " +
                    $"'{prefix}' contains '{character}'.");
                break;
            }
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
