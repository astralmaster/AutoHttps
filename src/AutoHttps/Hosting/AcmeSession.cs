using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

internal sealed class AcmeSession : IDisposable
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AutoHttpsOptions _options;
    private readonly IAccountKeyStore _accountKeyStore;
    private readonly ILogger<AcmeSession> _logger;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private AcmeClient? _client;
    private AcmeKey? _accountKey;
    private bool _registered;

    public AcmeSession(
        IHttpClientFactory httpClientFactory,
        IOptions<AutoHttpsOptions> options,
        IAccountKeyStore accountKeyStore,
        ILogger<AcmeSession> logger,
        TimeProvider time)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _accountKeyStore = accountKeyStore;
        _logger = logger;
        _time = time;
    }

    public async Task<AcmeClient> GetClientAsync(bool requireAccount, CancellationToken cancellationToken)
    {
        AcmeClient? cached = Volatile.Read(ref _client);
        if (cached is not null && (!requireAccount || Volatile.Read(ref _registered)))
        {
            return cached;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            AcmeClient client = _client ?? await CreateClientAsync(cancellationToken);

            // Kept before registration is attempted. Rebuilding the client on the next attempt would
            // generate a fresh account key, because the key is only written to the store once
            // registration has succeeded, and every retry would then ask the authority for another
            // account instead of retrying the one it already has.
            Volatile.Write(ref _client, client);

            if (requireAccount && !_registered)
            {
                await client.RegisterAccountAsync(
                    [BuildContact(_options.EmailAddress!)],
                    _options.AcceptTermsOfService,
                    _options.ExternalAccountBinding,
                    cancellationToken);

                await PersistAccountKeyAsync(cancellationToken);
                Volatile.Write(ref _registered, true);
            }

            return client;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Forgets that the account was registered, so the next request registers again with the same
    /// key. Used when the authority stops recognising the account, which happens if it was
    /// deactivated, if the endpoint moved, or if the authority lost the registration.
    /// </summary>
    public void InvalidateAccount() => Volatile.Write(ref _registered, false);

    public void Dispose()
    {
        _gate.Dispose();
        _accountKey?.Dispose();
    }

    private async Task<AcmeClient> CreateClientAsync(CancellationToken cancellationToken)
    {
        string name = AccountKeyName;
        string? existing = await _accountKeyStore.LoadAsync(name, cancellationToken);

        _accountKey = existing is null ? AcmeKey.CreateEcdsa() : AcmeKey.ImportPem(existing);

        var http = new AcmeHttpClient(
            _httpClientFactory,
            AutoHttpsDefaults.HttpClientName,
            _options.CertificateAuthority,
            _logger,
            _time);

        return new AcmeClient(http, _accountKey, _logger, _time);
    }

    private async Task PersistAccountKeyAsync(CancellationToken cancellationToken)
    {
        if (_accountKey is null)
        {
            return;
        }

        string name = AccountKeyName;
        if (await _accountKeyStore.LoadAsync(name, cancellationToken) is null)
        {
            await _accountKeyStore.SaveAsync(name, _accountKey.ExportPem(), cancellationToken);
        }
    }

    private string AccountKeyName => StoreKey.ForAccount(_options.CertificateAuthority, _options.EmailAddress ?? string.Empty);

    private static string BuildContact(string emailAddress) =>
        emailAddress.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ? emailAddress : "mailto:" + emailAddress;
}
