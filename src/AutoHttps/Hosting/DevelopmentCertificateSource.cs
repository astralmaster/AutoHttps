using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using AutoHttps.Certificates;
using AutoHttps.Internal;

namespace AutoHttps.Hosting;

/// <summary>
/// Where a development build gets the certificate it serves instead of ordering one over ACME.
/// Configured by <see cref="IAutoHttpsBuilder.UseDevelopmentCertificate()"/> and its overloads, and
/// only consulted when the host is running in the Development environment.
/// </summary>
internal sealed class DevelopmentCertificateSource
{
    private readonly Kind _kind;
    private readonly string? _path;
    private readonly string? _password;
    private readonly X509Certificate2? _certificate;

    private DevelopmentCertificateSource(Kind kind, string? path, string? password, X509Certificate2? certificate)
    {
        _kind = kind;
        _path = path;
        _password = password;
        _certificate = certificate;
    }

    private enum Kind
    {
        Disabled,
        AspNetDevelopmentCertificate,
        File,
        Certificate,
    }

    public static DevelopmentCertificateSource Disabled { get; } =
        new(Kind.Disabled, path: null, password: null, certificate: null);

    public static DevelopmentCertificateSource AspNetDevelopmentCertificate() =>
        new(Kind.AspNetDevelopmentCertificate, path: null, password: null, certificate: null);

    public static DevelopmentCertificateSource FromFile(string path, string? password) =>
        new(Kind.File, path, password, certificate: null);

    public static DevelopmentCertificateSource FromCertificate(X509Certificate2 certificate) =>
        new(Kind.Certificate, path: null, password: null, certificate);

    public bool IsEnabled => _kind != Kind.Disabled;

    /// <summary>A word for the log line, describing where the certificate came from.</summary>
    public string Description => _kind == Kind.AspNetDevelopmentCertificate ? "ASP.NET Core" : "supplied";

    /// <summary>
    /// Loads the certificate to serve, or returns <see langword="null"/> when the ASP.NET Core
    /// development certificate was asked for but is not installed.
    /// </summary>
    public X509Certificate2? Resolve(DateTimeOffset now) => _kind switch
    {
        Kind.AspNetDevelopmentCertificate => DevelopmentCertificateLocator.Find(now),
        Kind.File => LoadFile(),
        Kind.Certificate => _certificate,
        _ => null,
    };

    private X509Certificate2 LoadFile()
    {
        byte[] data = File.ReadAllBytes(_path!);
        return CertificateLoader.LoadPkcs12(data, _password, CertificateFactory.StorageFlags);
    }
}
