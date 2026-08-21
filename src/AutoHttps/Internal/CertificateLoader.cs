using System.Security.Cryptography.X509Certificates;

namespace AutoHttps.Internal;

internal static class CertificateLoader
{
    public static X509Certificate2 LoadPkcs12(byte[] data, string? password, X509KeyStorageFlags flags)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(data, password, flags);
#else
        return new X509Certificate2(data, password, flags);
#endif
    }

    public static X509Certificate2Collection LoadPkcs12Collection(byte[] data, string? password, X509KeyStorageFlags flags)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12Collection(data, password, flags);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(data, password, flags);
        return collection;
#endif
    }
}
