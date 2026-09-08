using System;
using Azure.Core;
using Azure.Identity;

namespace AutoHttps.Azure;

internal static class AzureCredentials
{
    /// <summary>
    /// A client-secret credential when all three parts are set, otherwise the default credential chain
    /// (managed identity, environment, Azure CLI, and so on).
    /// </summary>
    public static TokenCredential Create(string? tenantId, string? clientId, string? clientSecret)
    {
        if (!string.IsNullOrWhiteSpace(tenantId) &&
            !string.IsNullOrWhiteSpace(clientId) &&
            !string.IsNullOrWhiteSpace(clientSecret))
        {
            return new ClientSecretCredential(tenantId, clientId, clientSecret);
        }

        return new DefaultAzureCredential();
    }
}
