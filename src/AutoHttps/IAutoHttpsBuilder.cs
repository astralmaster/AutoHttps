using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Hosting;
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
    IAutoHttpsBuilder PersistCertificatesTo<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>()
        where TStore : class, ICertificateStore;

    /// <summary>Replaces the ACME account key store.</summary>
    /// <typeparam name="TStore">The store implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder PersistAccountKeyTo<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>()
        where TStore : class, IAccountKeyStore;

    /// <summary>
    /// Replaces the lock that stops several instances from ordering the same certificate at once.
    /// </summary>
    /// <typeparam name="TLock">The lock implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder UseDistributedLock<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TLock>()
        where TLock : class, IDistributedLock;

    /// <summary>Registers the provider that publishes DNS TXT records for <c>dns-01</c> challenges.</summary>
    /// <typeparam name="TProvider">The provider implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder UseDnsChallengeProvider<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TProvider>()
        where TProvider : class, IDnsChallengeProvider;

    /// <summary>
    /// Registers a listener notified when the served certificate changes or an order fails. Several
    /// may be registered; they are called in registration order.
    /// </summary>
    /// <typeparam name="TListener">The listener implementation.</typeparam>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder AddCertificateListener<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TListener>()
        where TListener : class, IAutoHttpsCertificateListener;

    /// <summary>
    /// Registers a listener instance notified when the served certificate changes or an order fails.
    /// </summary>
    /// <param name="listener">The listener.</param>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder AddCertificateListener(IAutoHttpsCertificateListener listener);

    /// <summary>
    /// In the Development environment, serve the ASP.NET Core HTTPS development certificate on
    /// localhost instead of ordering one over ACME. Run <c>dotnet dev-certs https --trust</c> once so
    /// the browser trusts it. Outside Development this call is ignored and the normal ACME path runs.
    /// </summary>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder UseDevelopmentCertificate();

    /// <summary>
    /// In the Development environment, serve the certificate in a PKCS#12 file instead of ordering one
    /// over ACME. This is the file <c>mkcert -pkcs12</c> produces, which lets a real hostname be used
    /// locally with a trusted certificate. Outside Development this call is ignored.
    /// </summary>
    /// <param name="certificatePath">Path to a PKCS#12 (<c>.pfx</c> or <c>.p12</c>) file.</param>
    /// <param name="password">The file's password, or <see langword="null"/> when it has none.</param>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder UseDevelopmentCertificate(string certificatePath, string? password = null);

    /// <summary>
    /// In the Development environment, serve the given certificate instead of ordering one over ACME.
    /// Outside Development this call is ignored. AutoHttps takes ownership of the certificate.
    /// </summary>
    /// <param name="certificate">The certificate to serve, which must carry its private key.</param>
    /// <returns>The builder.</returns>
    IAutoHttpsBuilder UseDevelopmentCertificate(X509Certificate2 certificate);
}

internal sealed class AutoHttpsBuilder : IAutoHttpsBuilder
{
    public AutoHttpsBuilder(IServiceCollection services) => Services = services;

    public IServiceCollection Services { get; }

    public IAutoHttpsBuilder PersistCertificatesTo<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>()
        where TStore : class, ICertificateStore
    {
        Services.Replace(ServiceDescriptor.Singleton<ICertificateStore, TStore>());
        return this;
    }

    public IAutoHttpsBuilder PersistAccountKeyTo<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>()
        where TStore : class, IAccountKeyStore
    {
        Services.Replace(ServiceDescriptor.Singleton<IAccountKeyStore, TStore>());
        return this;
    }

    public IAutoHttpsBuilder UseDistributedLock<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TLock>()
        where TLock : class, IDistributedLock
    {
        Services.Replace(ServiceDescriptor.Singleton<IDistributedLock, TLock>());
        return this;
    }

    public IAutoHttpsBuilder UseDnsChallengeProvider<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TProvider>()
        where TProvider : class, IDnsChallengeProvider
    {
        Services.Replace(ServiceDescriptor.Singleton<IDnsChallengeProvider, TProvider>());
        return this;
    }

    public IAutoHttpsBuilder AddCertificateListener<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TListener>()
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

    public IAutoHttpsBuilder UseDevelopmentCertificate() =>
        UseDevelopmentCertificate(DevelopmentCertificateSource.AspNetDevelopmentCertificate());

    public IAutoHttpsBuilder UseDevelopmentCertificate(string certificatePath, string? password = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificatePath);
        return UseDevelopmentCertificate(DevelopmentCertificateSource.FromFile(certificatePath, password));
    }

    public IAutoHttpsBuilder UseDevelopmentCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return UseDevelopmentCertificate(DevelopmentCertificateSource.FromCertificate(certificate));
    }

    private AutoHttpsBuilder UseDevelopmentCertificate(DevelopmentCertificateSource source)
    {
        Services.Replace(ServiceDescriptor.Singleton(source));
        return this;
    }
}
