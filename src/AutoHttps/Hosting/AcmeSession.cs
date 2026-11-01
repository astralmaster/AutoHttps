using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Certificates;
using AutoHttps.Internal;
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
    private bool _keyFromStore;
    private bool _registered;
    private string? _announcedAccount;

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
                if (!(_keyFromStore && await FindAccountAsync(client, cancellationToken)))
                {
                    await client.RegisterAccountAsync(
                        [BuildContact(_options.EmailAddress!)],
                        _options.AcceptTermsOfService,
                        _options.ExternalAccountBinding,
                        cancellationToken);
                }

                await PersistAccountKeyAsync(cancellationToken);
                Volatile.Write(ref _registered, true);
                AnnounceAccount(client.AccountUrl);
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
    /// key. Used when the authority stops recognising the account (accountDoesNotExist), which happens
    /// if the endpoint moved or the authority lost the registration. A deactivated account is not that
    /// case: the authority answers unauthorized for its key and refuses to register it again, so it is
    /// reported as a failed order with the authority's reason, and only removing the stored key gets a
    /// new account.
    /// </summary>
    public void InvalidateAccount() => Volatile.Write(ref _registered, false);

    /// <summary>
    /// The URL of the account in use, once one has been registered or found. A CAA accounturi has to
    /// name it exactly.
    /// </summary>
    public string? AccountUrl => Volatile.Read(ref _registered) ? Volatile.Read(ref _client)?.AccountUrl : null;

    public void Dispose()
    {
        _gate.Dispose();
        _accountKey?.Dispose();
    }

    /// <summary>
    /// Finds the account a stored key already has instead of registering again. Registering an
    /// existing key returns the same account, but it sends the external account binding again, and
    /// some authorities issue bindings that work once and expire within days: Google Trust Services
    /// keys are single use and last 7 days. An authority that checks the binding before matching the
    /// key would then refuse every restart after the first week.
    /// </summary>
    private async Task<bool> FindAccountAsync(AcmeClient client, CancellationToken cancellationToken)
    {
        try
        {
            return await client.FindAccountAsync(cancellationToken);
        }
        catch (AcmeException ex) when (ex is not AcmeRateLimitException && ex.StatusCode is >= 400 and < 500)
        {
            // RFC 8555 requires the lookup, but registering is what this did before it existed, so an
            // authority that refuses the lookup for some other reason still gets an account.
            Log.AccountLookupRefused(_logger, ex.Detail ?? ex.Message);
            return false;
        }
    }

    private async Task<AcmeClient> CreateClientAsync(CancellationToken cancellationToken)
    {
        string name = AccountKeyName;
        string? existing = await _accountKeyStore.LoadAsync(name, cancellationToken);

        _keyFromStore = existing is not null;
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

    /// <summary>
    /// Logs the account URL at Information the first time it is known, and again only if it changes.
    /// It is what a CAA accounturi has to name, and the registration itself is logged only at Debug.
    /// </summary>
    private void AnnounceAccount(string? accountUrl)
    {
        if (accountUrl is null || string.Equals(_announcedAccount, accountUrl, StringComparison.Ordinal))
        {
            return;
        }

        _announcedAccount = accountUrl;
        Log.AccountInUse(_logger, accountUrl, _options.CertificateAuthority);
    }

    private string AccountKeyName => StoreKey.ForAccount(_options.CertificateAuthority, _options.EmailAddress ?? string.Empty);

    private static string BuildContact(string emailAddress) =>
        emailAddress.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ? emailAddress : "mailto:" + emailAddress;
}
