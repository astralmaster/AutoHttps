using System;
using Azure.Core;
using Azure.Identity;

namespace AutoHttps.Azure;

internal static class AzureCredentials
{
    /// <summary>
    /// A client-secret credential when all three parts are set. A client id on its own picks that
    /// user-assigned managed identity, which is how one is chosen on a host that has several. With
    /// nothing set, the default credential chain (managed identity, environment, Azure CLI, and so on).
    /// </summary>
    public static TokenCredential Create(string? tenantId, string? clientId, string? clientSecret)
    {
        bool hasTenant = !string.IsNullOrWhiteSpace(tenantId);
        bool hasClient = !string.IsNullOrWhiteSpace(clientId);
        bool hasSecret = !string.IsNullOrWhiteSpace(clientSecret);

        if (hasTenant && hasClient && hasSecret)
        {
            return new ClientSecretCredential(tenantId, clientId, clientSecret);
        }

        // Anything between nothing and a complete service principal is a configuration mistake, such as
        // a misspelt key for the secret. Falling back to the default chain would sign in as some other
        // identity, with other permissions, and fail far from the cause.
        if (hasTenant || hasSecret)
        {
            throw new InvalidOperationException(
                "Azure credentials are only partly configured: a service principal needs TenantId, ClientId and " +
                "ClientSecret together, and a user-assigned managed identity needs ClientId alone. Set those, or " +
                "none of them to use DefaultAzureCredential.");
        }

        return new DefaultAzureCredential(CreateDefaultOptions(hasClient ? clientId : null));
    }

    internal static DefaultAzureCredentialOptions CreateDefaultOptions(string? managedIdentityClientId) =>
        new() { ManagedIdentityClientId = managedIdentityClientId };
}
