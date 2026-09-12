using System;
using AutoHttps.Azure;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoHttps.Azure.Tests;

public sealed class AzureKeyVaultOptionsValidatorTests
{
    private static readonly Uri Vault = new("https://v.vault.azure.net/");
    private readonly AzureKeyVaultOptionsValidator _validator = new();

    [Fact]
    public void OptionsWithAVaultUriAndTheDefaultPrefixAreValid()
    {
        ValidateOptionsResult result = _validator.Validate(null, new AzureKeyVaultOptions { VaultUri = Vault });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void AMissingVaultUriFails()
    {
        ValidateOptionsResult result = _validator.Validate(null, new AzureKeyVaultOptions());

        Assert.True(result.Failed);
        Assert.Contains("VaultUri", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("my_app-")]   // underscore
    [InlineData("app:")]      // colon
    [InlineData("prefix.")]   // dot
    public void APrefixWithCharactersKeyVaultRejectsFailsAndNamesTheOption(string prefix)
    {
        ValidateOptionsResult result = _validator.Validate(
            null, new AzureKeyVaultOptions { VaultUri = Vault, SecretPrefix = prefix });

        Assert.True(result.Failed);
        Assert.Contains("SecretPrefix", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void APrefixLongerThanTheBoundFailsAndNamesTheOption()
    {
        string prefix = new('a', AzureKeyVaultOptionsValidator.MaxPrefixLength + 1);

        ValidateOptionsResult result = _validator.Validate(
            null, new AzureKeyVaultOptions { VaultUri = Vault, SecretPrefix = prefix });

        Assert.True(result.Failed);
        Assert.Contains("SecretPrefix", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void APrefixAtTheMaximumLengthIsValidAndStillYieldsAValidSecretName()
    {
        string prefix = new('a', AzureKeyVaultOptionsValidator.MaxPrefixLength);

        ValidateOptionsResult result = _validator.Validate(
            null, new AzureKeyVaultOptions { VaultUri = Vault, SecretPrefix = prefix });
        Assert.True(result.Succeeded);

        // The worst case: the longest kind and an identifier that fills the 80-character body cap.
        string name = KeyVaultSecretNames.For(prefix, "account", new string('x', 200));
        Assert.True(name.Length <= 127, $"the composed secret name was {name.Length} characters");
        Assert.Matches("^[a-zA-Z0-9-]+$", name);
    }
}
