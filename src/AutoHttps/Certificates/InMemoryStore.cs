using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Certificates;

internal sealed class InMemoryStore : ICertificateStore, IAccountKeyStore
{
    private readonly ConcurrentDictionary<string, CertificateMaterial> _certificates = new(System.StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _accountKeys = new(System.StringComparer.Ordinal);

    public Task<CertificateMaterial?> LoadAsync(string name, CancellationToken cancellationToken) =>
        Task.FromResult(_certificates.TryGetValue(name, out CertificateMaterial? material) ? material : null);

    public Task SaveAsync(string name, CertificateMaterial material, CancellationToken cancellationToken)
    {
        _certificates[name] = material;
        return Task.CompletedTask;
    }

    Task<string?> IAccountKeyStore.LoadAsync(string name, CancellationToken cancellationToken) =>
        Task.FromResult(_accountKeys.TryGetValue(name, out string? key) ? key : null);

    Task IAccountKeyStore.SaveAsync(string name, string privateKeyPem, CancellationToken cancellationToken)
    {
        _accountKeys[name] = privateKeyPem;
        return Task.CompletedTask;
    }
}
