using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Certificates;
using AutoHttps.Internal;
using AutoHttps.Renewal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

internal sealed class AutoHttpsService : BackgroundService
{
    private static readonly TimeSpan DeferredPollInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan StartupGrace = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxIssueThrottle = TimeSpan.FromHours(1);
    private static readonly TimeSpan MaxRateLimitWait = TimeSpan.FromHours(1);

    private readonly AutoHttpsOptions _options;
    private readonly CertificateAcquirer _acquirer;
    private readonly CertificateSelector _selector;
    private readonly ICertificateStore _store;
    private readonly IDistributedLock _lock;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<AutoHttpsService> _logger;
    private readonly TimeProvider _time;
    private readonly AutoHttpsState _state;
    private readonly CertificateEventPublisher _events;
    private readonly AutoHttpsMetrics _metrics;

    private ServerCertificate? _current;
    private DateTimeOffset _loggedRenewal;
    private DateTimeOffset _lastIssued;
    private TimeSpan _nextRetry;
    private DateTimeOffset _rateLimitedUntil;

    public AutoHttpsService(
        IOptions<AutoHttpsOptions> options,
        CertificateAcquirer acquirer,
        CertificateSelector selector,
        ICertificateStore store,
        IDistributedLock distributedLock,
        IHostApplicationLifetime lifetime,
        ILogger<AutoHttpsService> logger,
        TimeProvider time,
        AutoHttpsState state,
        CertificateEventPublisher events,
        AutoHttpsMetrics metrics)
    {
        _options = options.Value;
        _acquirer = acquirer;
        _selector = selector;
        _store = store;
        _lock = distributedLock;
        _lifetime = lifetime;
        _logger = logger;
        _time = time;
        _state = state;
        _events = events;
        _metrics = metrics;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        IReadOnlyList<string> domains = DomainNormalizer.Normalize(_options.DomainNames);
        if (domains.Count == 0)
        {
            return;
        }

        string storeName = StoreKey.ForCertificate(_options.CertificateAuthority, domains);
        string description = string.Join(", ", domains);

        _state.SetDomains(domains);

        if (_options.ServeFallbackCertificate)
        {
            _selector.SetFallbackNames(domains);
        }

        Log.ServiceStarting(_logger, description);

        await AdoptFromStoreAsync(storeName, announce: false, stoppingToken);
        await WaitForApplicationStartedAsync(stoppingToken);

        _nextRetry = _options.InitialRetryDelay;

        while (!stoppingToken.IsCancellationRequested)
        {
            // Nothing in here may escape. A background service that throws takes the whole host down
            // with it by default, and losing the application because a certificate could not be
            // renewed is far worse than continuing to serve the certificate already in hand.
            try
            {
                await RunOnceAsync(domains, storeName, description, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                Log.UnexpectedFailure(_logger, description, _nextRetry, ex);
                await DelayAsync(_nextRetry, stoppingToken);
                _nextRetry = Min(_nextRetry + _nextRetry, _options.MaxRetryDelay);
            }
        }
    }

    private async Task RunOnceAsync(
        IReadOnlyList<string> domains,
        string storeName,
        string description,
        CancellationToken stoppingToken)
    {
        _selector.CollectRetired();

        DateTimeOffset now = _time.GetUtcNow();
        DateTimeOffset renewAt = await ComputeRenewalTimeAsync(now, stoppingToken);

        if (renewAt > now)
        {
            LogSchedule(description, renewAt);
            await DelayAsync(Min(renewAt - now, _options.RenewalCheckInterval), stoppingToken);
            return;
        }

        if (_rateLimitedUntil > now)
        {
            await DelayAsync(Min(_rateLimitedUntil - now, MaxRateLimitWait), stoppingToken);
            return;
        }

        if (TryGetIssueThrottle(now, out TimeSpan throttle))
        {
            Log.RenewalThrottled(_logger, description, throttle);
            await DelayAsync(throttle, stoppingToken);
            return;
        }

        switch (await TryAcquireAsync(domains, storeName, description, stoppingToken))
        {
            case AcquisitionOutcome.Acquired:
                _nextRetry = _options.InitialRetryDelay;
                _lastIssued = _time.GetUtcNow();
                break;

            case AcquisitionOutcome.Deferred:
                await DelayAsync(DeferredPollInterval, stoppingToken);
                break;

            case AcquisitionOutcome.Failed:
                await DelayAsync(_nextRetry, stoppingToken);
                _nextRetry = Min(_nextRetry + _nextRetry, _options.MaxRetryDelay);
                break;
        }
    }

    private async Task<AcquisitionOutcome> TryAcquireAsync(
        IReadOnlyList<string> domains,
        string storeName,
        string description,
        CancellationToken cancellationToken)
    {
        IAsyncDisposable? handle = await _lock.TryAcquireAsync(storeName, cancellationToken);

        if (handle is null)
        {
            Log.LockUnavailable(_logger, description);
            await AdoptFromStoreAsync(storeName, announce: true, cancellationToken);
            return AcquisitionOutcome.Deferred;
        }

        await using (handle)
        {
            if (await AdoptFromStoreAsync(storeName, announce: true, cancellationToken) && !IsDue(_current))
            {
                return AcquisitionOutcome.Acquired;
            }

            bool renewing = _current is not null;

            try
            {
                string? replaces = TryGetCertificateId(_current);
                CertificateMaterial material = await _acquirer.AcquireAsync(domains, replaces, cancellationToken);

                ServerCertificate certificate = CertificateFactory.CreateFromPem(
                    material.CertificateChainPem, material.PrivateKeyPem);

                // Persist before serving. A process that dies between the two would otherwise come
                // back with nothing on disk and order all over again, which is the quickest way to
                // run into a certificate authority's duplicate-certificate limit.
                await SaveAsync(storeName, material, cancellationToken);

                Publish(certificate);
                Log.CertificateIssued(_logger, description, certificate.NotAfter);
                _metrics.RecordSuccess();
                await NotifyChangedAsync(
                    certificate,
                    renewing ? CertificateChangeReason.Renewed : CertificateChangeReason.Issued,
                    cancellationToken);

                return AcquisitionOutcome.Acquired;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (AcmeRateLimitException ex)
            {
                // The authority said when it will accept another request. Ignoring that only digs
                // the hole deeper, so its instruction overrides the local backoff.
                if (ex.RetryAfter is { } retryAfter && retryAfter > _time.GetUtcNow())
                {
                    _rateLimitedUntil = retryAfter;
                    Log.RateLimited(_logger, description, retryAfter);
                }

                Log.OrderFailed(_logger, description, Describe(ex), _nextRetry);
                Log.OrderFailedDetail(_logger, description, ex);
                await ReportFailureAsync(ex, cancellationToken);
                return AcquisitionOutcome.Failed;
            }
            catch (Exception ex)
            {
                Log.OrderFailed(_logger, description, Describe(ex), _nextRetry);
                Log.OrderFailedDetail(_logger, description, ex);
                await ReportFailureAsync(ex, cancellationToken);
                return AcquisitionOutcome.Failed;
            }
        }
    }

    private async Task<DateTimeOffset> ComputeRenewalTimeAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        ServerCertificate? current = _current;
        if (current is null)
        {
            return now;
        }

        RenewalWindow? window = null;
        if (AcmeCertificateId.TryCompute(current.Leaf, out string certificateId))
        {
            try
            {
                window = (await _acquirer.GetRenewalWindowAsync(certificateId, cancellationToken)).Window;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.RenewalInfoUnavailable(_logger, certificateId, ex);
            }
        }

        return RenewalCalculator.ComputeRenewalTime(
            current.NotBefore,
            current.NotAfter,
            window,
            current.Leaf.SerialNumberBytes.Span,
            _options.RenewalThreshold,
            now);
    }

    /// <summary>
    /// Guards against a configuration in which a freshly issued certificate immediately qualifies
    /// for renewal, which would otherwise order certificates in a tight loop until the authority
    /// starts refusing them.
    /// </summary>
    private bool TryGetIssueThrottle(DateTimeOffset now, out TimeSpan delay)
    {
        delay = TimeSpan.Zero;

        if (_lastIssued == default)
        {
            return false;
        }

        TimeSpan minimumInterval = Min(_options.RenewalCheckInterval, MaxIssueThrottle);
        TimeSpan elapsed = now - _lastIssued;

        if (elapsed >= minimumInterval)
        {
            return false;
        }

        delay = minimumInterval - elapsed;
        return true;
    }

    private bool IsDue(ServerCertificate? certificate)
    {
        if (certificate is null)
        {
            return true;
        }

        DateTimeOffset now = _time.GetUtcNow();
        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            certificate.NotBefore,
            certificate.NotAfter,
            suggestedWindow: null,
            certificate.Leaf.SerialNumberBytes.Span,
            _options.RenewalThreshold,
            now);

        return renewAt <= now;
    }

    private async Task<bool> AdoptFromStoreAsync(string storeName, bool announce, CancellationToken cancellationToken)
    {
        CertificateMaterial? material;
        try
        {
            material = await _store.LoadAsync(storeName, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.StoreReadFailed(_logger, ex);
            return false;
        }

        if (material is null)
        {
            return false;
        }

        ServerCertificate candidate;
        try
        {
            candidate = CertificateFactory.CreateFromPem(material.CertificateChainPem, material.PrivateKeyPem);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.StoreReadFailed(_logger, ex);
            return false;
        }

        // Only expiry disqualifies a stored certificate. One whose validity has not started yet is
        // still the best thing available, and ordering another would just produce the same result:
        // authorities differ on how far they backdate, and a machine whose clock has not synced
        // sees its own fresh certificate as being from the future.
        DateTimeOffset now = _time.GetUtcNow();
        bool usable = candidate.NotAfter > now && !IsSameCertificate(_current, candidate);

        if (!usable)
        {
            candidate.Dispose();
            return false;
        }

        Publish(candidate);
        string subjects = string.Join(", ", candidate.SubjectNames);

        if (announce)
        {
            Log.CertificateAdopted(_logger, subjects);
            await NotifyChangedAsync(candidate, CertificateChangeReason.Adopted, cancellationToken);
        }
        else
        {
            // A certificate this instance loaded from its own store at startup is what it was already
            // serving, so it is not reported as a change; only the state readers are updated.
            Log.CertificateLoaded(_logger, subjects, candidate.NotAfter);
        }

        return true;
    }

    private async Task SaveAsync(string storeName, CertificateMaterial material, CancellationToken cancellationToken)
    {
        try
        {
            await _store.SaveAsync(storeName, material, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.StoreWriteFailed(_logger, ex);
        }
    }

    private void Publish(ServerCertificate certificate)
    {
        // Update the read model before handing the certificate to the selector. The selector's
        // publish is a full barrier, so a reader that sees the new certificate there is guaranteed to
        // also see the matching state, never a certificate the inspector does not yet know about.
        _current = certificate;
        _state.CertificatePublished(certificate);
        _selector.Publish(certificate);
        _loggedRenewal = default;
    }

    private Task NotifyChangedAsync(
        ServerCertificate certificate,
        CertificateChangeReason reason,
        CancellationToken cancellationToken)
    {
        var context = new CertificateChangedContext(
            _state.Current.Domains,
            certificate.SubjectNames,
            certificate.NotBefore,
            certificate.NotAfter,
            certificate.Leaf.Thumbprint,
            reason);

        return _events.NotifyChangedAsync(context, cancellationToken);
    }

    private Task ReportFailureAsync(Exception exception, CancellationToken cancellationToken)
    {
        string reason = Describe(exception);
        _state.OrderFailed(_time.GetUtcNow(), reason);
        _metrics.RecordFailure();

        var context = new CertificateFailedContext(_state.Current.Domains, reason, exception);
        return _events.NotifyFailedAsync(context, cancellationToken);
    }

    private void LogSchedule(string description, DateTimeOffset renewAt)
    {
        _state.RenewalScheduled(renewAt);

        if (_loggedRenewal == renewAt)
        {
            return;
        }

        _loggedRenewal = renewAt;
        Log.RenewalScheduled(_logger, description, renewAt);
    }

    private async Task WaitForApplicationStartedAsync(CancellationToken cancellationToken)
    {
        if (_lifetime.ApplicationStarted.IsCancellationRequested)
        {
            return;
        }

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        using (_lifetime.ApplicationStarted.Register(static state => ((TaskCompletionSource)state!).TrySetResult(), started))
        using (cancellationToken.Register(static state => ((TaskCompletionSource)state!).TrySetResult(), started))
        {
            // A challenge cannot be answered before the server is listening. The grace period keeps a
            // host that never signals startup from blocking certificate acquisition forever. The timer
            // is deliberately not cancellable, so the losing task never faults unobserved.
            await Task.WhenAny(started.Task, Task.Delay(StartupGrace, _time, CancellationToken.None));
        }
    }

    private async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, _time, cancellationToken);
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>
    /// Reduces an exception to the sentence an operator needs. Certificate authorities put the
    /// useful part in the message, so the chain of causes matters more than the stack.
    /// </summary>
    private static string Describe(Exception exception)
    {
        string message = exception.Message;

        for (Exception? inner = exception.InnerException; inner is not null; inner = inner.InnerException)
        {
            message += " -> " + inner.Message;
        }

        return message.EndsWith('.') ? message : message + ".";
    }

    private static bool IsSameCertificate(ServerCertificate? left, ServerCertificate right) =>
        left is not null && string.Equals(left.Leaf.Thumbprint, right.Leaf.Thumbprint, StringComparison.Ordinal);

    private static string? TryGetCertificateId(ServerCertificate? certificate) =>
        certificate is not null && AcmeCertificateId.TryCompute(certificate.Leaf, out string id) ? id : null;

    private static TimeSpan Min(TimeSpan left, TimeSpan right) => left < right ? left : right;

    private enum AcquisitionOutcome
    {
        Acquired,
        Deferred,
        Failed,
    }
}
