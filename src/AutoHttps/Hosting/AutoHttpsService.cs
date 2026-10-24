using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
    private readonly IHostEnvironment _environment;
    private readonly DevelopmentCertificateSource _developmentCertificate;
    private readonly IAutoHttpsDiagnostics _diagnostics;

    private readonly TaskCompletionSource _firstCertificate = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private ServerCertificate? _current;
    private IReadOnlyList<string> _domains = [];
    private string _latestName = string.Empty;
    private string? _keyMismatchReported;
    private DateTimeOffset _loggedRenewal;
    private DateTimeOffset _lastIssued;
    private TimeSpan _nextRetry;
    private DateTimeOffset _rateLimitedUntil;
    private int _diagnosed;
    private bool _overdueReported;

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
        AutoHttpsMetrics metrics,
        IHostEnvironment environment,
        DevelopmentCertificateSource developmentCertificate,
        IAutoHttpsDiagnostics diagnostics)
    {
        _options = options.Value;
        _acquirer = acquirer;
        _selector = selector;
        _store = store;
        _lifetime = lifetime;
        _lock = distributedLock;
        _logger = logger;
        _time = time;
        _state = state;
        _events = events;
        _metrics = metrics;
        _environment = environment;
        _developmentCertificate = developmentCertificate;
        _diagnostics = diagnostics;
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

        _domains = domains;
        _latestName = StoreKey.ForLatest(_options.CertificateAuthority);
        _state.SetDomains(domains);

        if (_options.ServeFallbackCertificate)
        {
            _selector.SetFallbackNames(domains);
        }

        if (_developmentCertificate.IsEnabled && _environment.IsDevelopment())
        {
            ServeDevelopmentCertificate(description);
            return;
        }

        Log.ServiceStarting(_logger, description);

        if (_store is not FileSystemStore && _lock is FileSystemLock local)
        {
            // A store other instances can read, with a lock only this machine can see, is the setup in
            // which every replica orders its own certificate at the same moment. It is also a correct
            // setup for a single instance, so this is said once and not treated as an error.
            Log.LockNotShared(_logger, _store.GetType().Name, local.Root);
        }

        if (await AdoptFromStoreAsync(storeName, announce: false, stoppingToken) is { } stored)
        {
            // Kept so a later change of the configured names still finds this certificate. Done here
            // as well as after issuance so a store written before the copy existed gains one too.
            await RememberAsLatestAsync(stored, compareFirst: true, stoppingToken);
        }
        else
        {
            await AdoptPreviousAsync(storeName, description, stoppingToken);
        }

        await WaitForApplicationStartedAsync(stoppingToken);

        if (_options.RequireCertificateOnStartup && _current is null)
        {
            _ = WatchStartupCertificateAsync(description, stoppingToken);
        }

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
                await DelayAsync(JitterRetry(), stoppingToken);
                _nextRetry = Min(_nextRetry + _nextRetry, RetryCeiling());
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
        (DateTimeOffset renewAt, DateTimeOffset? recheckAt) = await ComputeRenewalTimeAsync(now, stoppingToken);

        if (renewAt > now)
        {
            LogSchedule(description, renewAt);
            await DelayAsync(
                RenewalSchedule.ComputeCheckDelay(now, renewAt, recheckAt, _options.RenewalCheckInterval, DeferredPollInterval),
                stoppingToken);
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
                _state.OrderSucceeded();
                _overdueReported = false;
                break;

            case AcquisitionOutcome.Deferred:
                await DelayAsync(DeferredPollInterval, stoppingToken);
                break;

            case AcquisitionOutcome.Failed:
                await DelayAsync(JitterRetry(), stoppingToken);
                _nextRetry = Min(_nextRetry + _nextRetry, RetryCeiling());
                break;
        }
    }

    private async Task<AcquisitionOutcome> TryAcquireAsync(
        IReadOnlyList<string> domains,
        string storeName,
        string description,
        CancellationToken cancellationToken)
    {
        IAsyncDisposable? handle;
        try
        {
            handle = await _lock.TryAcquireAsync(storeName, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // A lock that cannot be taken stops every order as surely as a failed one, which is what a
            // storage directory that cannot be written looks like, so it is counted the same way: the
            // failure count, the overdue escalation, the listeners and the diagnostics all hear of it.
            // It keeps event 122, because retrying does not fix it.
            Log.UnexpectedFailure(_logger, description, _nextRetry, ex);
            await ReportFailureAsync(ex, cancellationToken);
            return AcquisitionOutcome.Failed;
        }

        if (handle is null)
        {
            Log.LockUnavailable(_logger, description);
            await AdoptFromStoreAsync(storeName, announce: true, cancellationToken);
            return AcquisitionOutcome.Deferred;
        }

        await using (handle)
        {
            if (await AdoptFromStoreAsync(storeName, announce: true, cancellationToken) is not null && !IsDue(_current))
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
                await RememberAsLatestAsync(material, compareFirst: false, cancellationToken);

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
                // the hole deeper, so its instruction overrides the local backoff, but never so far
                // out that renewal would be suspended until the certificate expires. See
                // RateLimit.ClampDeadline.
                DateTimeOffset now = _time.GetUtcNow();
                if (ex.RetryAfter is { } retryAfter && retryAfter > now)
                {
                    DateTimeOffset deadline = RateLimit.ClampDeadline(retryAfter, now, _current?.NotAfter, MaxRateLimitWait);
                    _rateLimitedUntil = deadline;

                    if (deadline < retryAfter)
                    {
                        Log.RateLimitCapped(_logger, description, retryAfter, deadline);
                    }
                    else
                    {
                        Log.RateLimited(_logger, description, deadline);
                    }
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

    private async Task<(DateTimeOffset RenewAt, DateTimeOffset? RecheckAt)> ComputeRenewalTimeAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ServerCertificate? current = _current;
        if (current is null || !MatchesConfiguration(current))
        {
            // A certificate that leaves out a configured name, or has a key of a different kind than
            // configured, is only being served until one that matches is issued, so it is due now
            // whatever its own schedule says.
            return (now, null);
        }

        RenewalWindow? window = null;
        DateTimeOffset? recheckAt = null;

        // RFC 9773 section 4.3: do not ask for renewal information about a certificate that has already
        // expired. It is being replaced regardless, so the query would only waste a request each loop.
        if (current.NotAfter > now && AcmeCertificateId.TryCompute(current.Leaf, out string certificateId))
        {
            try
            {
                RenewalWindowResult info = await _acquirer.GetRenewalWindowAsync(certificateId, cancellationToken);
                window = info.Window;
                recheckAt = info.RecheckAt;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.RenewalInfoUnavailable(_logger, certificateId, ex);
            }
        }

        DateTimeOffset renewAt = RenewalCalculator.ComputeRenewalTime(
            current.NotBefore,
            current.NotAfter,
            window,
            current.Leaf.SerialNumberBytes.Span,
            _options.RenewalThreshold,
            now);
        return (renewAt, recheckAt);
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
        if (certificate is null || !MatchesConfiguration(certificate))
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

    /// <summary>Serves the certificate stored under this name, and returns what was stored if it was used.</summary>
    private async Task<CertificateMaterial?> AdoptFromStoreAsync(string storeName, bool announce, CancellationToken cancellationToken)
    {
        CertificateMaterial? material;
        try
        {
            material = await _store.LoadAsync(storeName, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.StoreReadFailed(_logger, ex);
            return null;
        }

        if (material is null)
        {
            return null;
        }

        ServerCertificate candidate;
        try
        {
            candidate = CertificateFactory.CreateFromPem(material.CertificateChainPem, material.PrivateKeyPem);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.StoreReadFailed(_logger, ex);
            return null;
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
            return null;
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

        return material;
    }

    /// <summary>
    /// When nothing is stored for the configured names, serves the most recent certificate from this
    /// authority for the names it covers. That is the case right after the configured names changed:
    /// without it every name, including the ones that stayed, would get the self-signed fallback until
    /// a certificate for the new set is issued, which never happens while a new name cannot validate.
    /// It is replaced at once, because <see cref="CoversConfiguredNames"/> makes it due.
    /// </summary>
    private async Task AdoptPreviousAsync(string storeName, string description, CancellationToken cancellationToken)
    {
        CertificateMaterial? material;
        try
        {
            material = await _store.LoadAsync(_latestName, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.StoreReadFailed(_logger, ex);
            return;
        }

        if (material is null)
        {
            return;
        }

        ServerCertificate candidate;
        try
        {
            candidate = CertificateFactory.CreateFromPem(material.CertificateChainPem, material.PrivateKeyPem);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.StoreReadFailed(_logger, ex);
            return;
        }

        string[] covered = [.. _domains.Where(domain => Names(candidate, domain))];

        // A certificate for none of these names, for example another application's when several share
        // the storage directory, is of no use here.
        if (candidate.NotAfter <= _time.GetUtcNow() || covered.Length == 0)
        {
            candidate.Dispose();
            return;
        }

        Publish(candidate);

        if (covered.Length == _domains.Count)
        {
            // Every configured name is in it, as after a name was removed, so it is filed under the
            // new set and kept until its ordinary renewal rather than replaced straight away.
            await SaveAsync(storeName, material, cancellationToken);
            string subjects = string.Join(", ", candidate.SubjectNames);
            Log.CertificateLoaded(_logger, subjects, candidate.NotAfter);
            return;
        }

        string coveredNames = string.Join(", ", covered);
        Log.PreviousCertificateServed(_logger, description, coveredNames);
    }

    /// <summary>
    /// Keeps a copy of the certificate in hand under a name that does not depend on the configured
    /// names, which is what <see cref="AdoptPreviousAsync"/> reads after they change. Losing it only
    /// loses that fallback, so a failure is logged and otherwise ignored.
    /// </summary>
    private async Task RememberAsLatestAsync(CertificateMaterial material, bool compareFirst, CancellationToken cancellationToken)
    {
        try
        {
            if (compareFirst &&
                await _store.LoadAsync(_latestName, cancellationToken) is { } latest &&
                string.Equals(latest.CertificateChainPem, material.CertificateChainPem, StringComparison.Ordinal))
            {
                return;
            }

            await _store.SaveAsync(_latestName, material, CancellationToken.None);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LatestCertificateNotRecorded(_logger, ex);
        }
    }

    /// <summary>
    /// Whether the certificate is what the options would order now. One that is not is kept in use,
    /// because it is still valid for the names it has, and replaced straight away rather than at its
    /// ordinary renewal, which could be two months off.
    /// </summary>
    private bool MatchesConfiguration(ServerCertificate certificate)
    {
        if (!CoversConfiguredNames(certificate))
        {
            return false;
        }

        if (CertificateKey.Matches(certificate.Leaf, _options.KeyAlgorithm))
        {
            return true;
        }

        if (!string.Equals(_keyMismatchReported, certificate.Leaf.Thumbprint, StringComparison.Ordinal))
        {
            _keyMismatchReported = certificate.Leaf.Thumbprint;
            string domains = string.Join(", ", _domains);
            Log.KeyAlgorithmChanged(_logger, domains, _options.KeyAlgorithm);
        }

        return false;
    }

    /// <summary>
    /// Whether the certificate names every configured domain. The names have to appear as they were
    /// configured: a wildcard that happens to match a configured name is not what was ordered for it.
    /// </summary>
    private bool CoversConfiguredNames(ServerCertificate certificate)
    {
        foreach (string domain in _domains)
        {
            if (!Names(certificate, domain))
            {
                return false;
            }
        }

        return true;
    }

    private static bool Names(ServerCertificate certificate, string domain)
    {
        foreach (string name in certificate.SubjectNames)
        {
            if (string.Equals(name, domain, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
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

    private void ServeDevelopmentCertificate(string description)
    {
        X509Certificate2? leaf = _developmentCertificate.Resolve(_time.GetUtcNow());
        if (leaf is null)
        {
            // Only the ASP.NET Core development certificate can be missing here; a supplied one or a
            // file would have thrown. The self-signed fallback keeps the app serving in the meantime.
            Log.DevelopmentCertificateMissing(_logger);
            return;
        }

        Publish(new ServerCertificate(leaf, new X509Certificate2Collection()), development: true);
        Log.DevelopmentCertificateServed(_logger, _developmentCertificate.Description, description);
    }

    private void Publish(ServerCertificate certificate, bool development = false)
    {
        // A development certificate is served for whatever names it has, by design, so it is not
        // reported as falling short of the configured ones.
        IReadOnlyList<string> uncovered = development
            ? []
            : [.. _domains.Where(domain => !Names(certificate, domain))];

        // Update the read model before handing the certificate to the selector. The selector's
        // publish is a full barrier, so a reader that sees the new certificate there is guaranteed to
        // also see the matching state, never a certificate the inspector does not yet know about.
        _current = certificate;
        _state.CertificatePublished(certificate, uncovered);
        _selector.Publish(certificate);
        _loggedRenewal = default;
        _firstCertificate.TrySetResult();
    }

    /// <summary>
    /// Stops the application if no real certificate is in hand within the configured window. A
    /// certificate adopted from the store already sets <see cref="_firstCertificate"/>, so this only
    /// fires when the first one genuinely cannot be obtained.
    /// </summary>
    private async Task WatchStartupCertificateAsync(string description, CancellationToken stoppingToken)
    {
        try
        {
            Task timeout = Task.Delay(_options.StartupCertificateTimeout, _time, stoppingToken);
            Task completed = await Task.WhenAny(_firstCertificate.Task, timeout);

            if (completed == _firstCertificate.Task || stoppingToken.IsCancellationRequested)
            {
                return;
            }

            Log.StartupCertificateTimedOut(_logger, description, _options.StartupCertificateTimeout);

            // Stopping alone ends the process with exit code 0, which restart policies such as systemd's
            // Restart=on-failure and Docker's on-failure read as a clean shutdown, so the instance would
            // stay down instead of being restarted. An exit code the application set already is kept.
            if (Environment.ExitCode == 0)
            {
                Environment.ExitCode = 1;
            }

            _lifetime.StopApplication();
        }
        catch (OperationCanceledException)
        {
        }
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

    private async Task ReportFailureAsync(Exception exception, CancellationToken cancellationToken)
    {
        string reason = Describe(exception);
        DateTimeOffset now = _time.GetUtcNow();
        _state.OrderFailed(now, reason);
        _metrics.RecordFailure();

        ReportOverdue(now, reason);

        var context = new CertificateFailedContext(_state.Current.Domains, reason, exception);
        await _events.NotifyFailedAsync(context, cancellationToken);

        await DiagnoseOnceAsync(cancellationToken);
    }

    /// <summary>
    /// Escalates once failures have outlasted the runway the renewal threshold left. Event 110
    /// already reports every attempt, which is the wrong thing to page on because most failures are
    /// retried successfully; this fires only while the certificate in use is inside the near-expiry
    /// window, and only once per run of failures, so a long outage does not become a stream of
    /// identical errors.
    /// </summary>
    private void ReportOverdue(DateTimeOffset now, string reason)
    {
        AutoHttpsState.Snapshot snapshot = _state.Current;

        if (_overdueReported || snapshot.Certificate is not { } certificate)
        {
            return;
        }

        bool overdue = RenewalRisk.IsOverdue(
            now,
            certificate.NotBefore,
            certificate.NotAfter,
            RenewalRisk.EffectiveNearExpiryFraction(_options.NearExpiryWarningFraction, _options.RenewalThreshold),
            snapshot.ConsecutiveFailures);

        if (!overdue)
        {
            return;
        }

        _overdueReported = true;
        Log.RenewalOverdue(
            _logger,
            string.Join(", ", snapshot.Domains),
            snapshot.ConsecutiveFailures,
            certificate.NotAfter,
            reason);
    }

    /// <summary>
    /// The ceiling for the retry backoff. While a certificate is in hand the ceiling is also held to
    /// a share of its lifetime, so a value chosen for a 90 day certificate does not leave a six day
    /// one with only a couple of attempts between the renewal point and expiry.
    /// </summary>
    private TimeSpan RetryCeiling() =>
        _current is { } certificate
            ? RenewalRisk.RetryCeiling(_options.MaxRetryDelay, certificate.NotBefore, certificate.NotAfter)
            : _options.MaxRetryDelay;

    /// <summary>
    /// Reports what is wrong the first time an order fails. The authority only says what it saw from
    /// outside, which is rarely enough to act on, and running this on every retry would be noise.
    /// </summary>
    private async Task DiagnoseOnceAsync(CancellationToken cancellationToken)
    {
        if (!_options.DiagnoseOrderFailures || Interlocked.Exchange(ref _diagnosed, 1) == 1)
        {
            return;
        }

        try
        {
            AutoHttpsDiagnosticsReport report = await _diagnostics.RunAsync(cancellationToken);

            if (report.Outcome is AutoHttpsCheckOutcome.Failed or AutoHttpsCheckOutcome.Warning)
            {
                Log.DiagnosticsFoundProblems(_logger, Environment.NewLine + report);
            }
            else
            {
                Log.DiagnosticsFoundNothing(_logger, Environment.NewLine + report);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Diagnosing a failure must never make the failure worse.
            Log.DiagnosticsFailed(_logger, ex);
        }
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

    private TimeSpan JitterRetry() => RetryBackoff.Jitter(_nextRetry, Random.Shared.NextDouble());

    private static TimeSpan Min(TimeSpan left, TimeSpan right) => left < right ? left : right;

    private enum AcquisitionOutcome
    {
        Acquired,
        Deferred,
        Failed,
    }
}
