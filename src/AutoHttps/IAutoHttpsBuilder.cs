using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AutoHttps;

/// <summary>
/// Replaces the components AutoHttps uses for storage, locking and DNS.
/// </summary>
public interface IAutoHttpsBuilder
{
    /// <summary>Gets the service collection AutoHttps was added to.</summary>
    IServiceCollection Services { get; }

    /// <summary>Replaces the certificate store.</summary>
    /// <typeparam name="TStore">The store implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder PersistCertificatesTo<TStore>()
        where TStore : class, ICertificateStore;

    /// <summary>Replaces the ACME account key store.</summary>
    /// <typeparam name="TStore">The store implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder PersistAccountKeyTo<TStore>()
        where TStore : class, IAccountKeyStore;

    /// <summary>
    /// Replaces the lock that stops several instances from ordering the same certificate at once.
    /// </summary>
    /// <typeparam name="TLock">The lock implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder UseDistributedLock<TLock>()
        where TLock : class, IDistributedLock;

    /// <summary>Registers the provider that publishes DNS TXT records for <c>dns-01</c> challenges.</summary>
    /// <typeparam name="TProvider">The provider implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder UseDnsChallengeProvider<TProvider>()
        where TProvider : class, IDnsChallengeProvider;
}

internal sealed class AutoHttpsBuilder : IAutoHttpsBuilder
{
    public AutoHttpsBuilder(IServiceCollection services) => Services = services;

    public IServiceCollection Services { get; }

    public IAutoHttpsBuilder PersistCertificatesTo<TStore>()
        where TStore : class, ICertificateStore
    {
        Services.Replace(ServiceDescriptor.Singleton<ICertificateStore, TStore>());
        return this;
    }

    public IAutoHttpsBuilder PersistAccountKeyTo<TStore>()
        where TStore : class, IAccountKeyStore
    {
        Services.Replace(ServiceDescriptor.Singleton<IAccountKeyStore, TStore>());
        return this;
    }

    public IAutoHttpsBuilder UseDistributedLock<TLock>()
        where TLock : class, IDistributedLock
    {
        Services.Replace(ServiceDescriptor.Singleton<IDistributedLock, TLock>());
        return this;
    }

    public IAutoHttpsBuilder UseDnsChallengeProvider<TProvider>()
        where TProvider : class, IDnsChallengeProvider
    {
        Services.Replace(ServiceDescriptor.Singleton<IDnsChallengeProvider, TProvider>());
        return this;
    }
}
