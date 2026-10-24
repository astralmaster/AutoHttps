using System;
using AutoHttps.Azure;
using Azure.Core;
using Azure.Identity;
using Xunit;

namespace AutoHttps.Azure.Tests;

/// <summary>
/// Which identity AutoHttps signs in as. Getting this wrong does not fail where it is configured. It
/// fails later as a permission error on some other identity, far from the cause.
/// </summary>
public sealed class AzureCredentialsTests
{
    [Fact]
    public void ACompleteServicePrincipalIsUsedAsOne()
    {
        TokenCredential credential = AzureCredentials.Create("tenant", "client", "secret");

        Assert.IsType<ClientSecretCredential>(credential);
    }

    [Fact]
    public void NothingSetUsesTheDefaultChain()
    {
        Assert.IsType<DefaultAzureCredential>(AzureCredentials.Create(null, null, null));
        Assert.Null(AzureCredentials.CreateDefaultOptions(null).ManagedIdentityClientId);
    }

    [Fact]
    public void AClientIdOnItsOwnPicksThatManagedIdentity()
    {
        // On a host with several user-assigned identities, the client id is how one is chosen. Ignoring
        // it left DefaultAzureCredential to fail or to pick another.
        Assert.IsType<DefaultAzureCredential>(AzureCredentials.Create(null, "managed-identity-client", null));
        Assert.Equal("managed-identity-client", AzureCredentials.CreateDefaultOptions("managed-identity-client").ManagedIdentityClientId);
    }

    [Theory]
    [InlineData("tenant", "client", null)]
    [InlineData("tenant", null, "secret")]
    [InlineData(null, "client", "secret")]
    [InlineData("tenant", null, null)]
    [InlineData(null, null, "secret")]
    public void APartlyConfiguredServicePrincipalIsRefused(string? tenantId, string? clientId, string? clientSecret)
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => AzureCredentials.Create(tenantId, clientId, clientSecret));

        Assert.Contains("ClientSecret", error.Message, StringComparison.Ordinal);
    }
}
