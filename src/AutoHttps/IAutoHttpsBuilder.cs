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

    /// <summary>
    /// Registers a listener notified when the served certificate changes or an order fails. Several
    /// may be registered; they are called in registration order.
    /// </summary>
    /// <typeparam name="TListener">The listener implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder AddCertificateListener<TListener>()
        where TListener : class, IAutoHttpsCertificateListener;

    /// <summary>
    /// Registers a listener instance notified when the served certificate changes or an order fails.
    /// </summary>
    /// <param name="listener">The listener.</param>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder AddCertificateListener(IAutoHttpsCertificateListener listener);
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

    public IAutoHttpsBuilder AddCertificateListener<TListener>()
        where TListener : class, IAutoHttpsCertificateListener
    {
        Services.TryAddEnumerable(ServiceDescriptor.Singleton<IAutoHttpsCertificateListener, TListener>());
        return this;
    }

    public IAutoHttpsBuilder AddCertificateListener(IAutoHttpsCertificateListener listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        Services.TryAddEnumerable(ServiceDescriptor.Singleton(listener));
        return this;
    }
}
