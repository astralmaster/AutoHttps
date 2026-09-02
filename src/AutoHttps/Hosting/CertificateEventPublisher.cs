using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Internal;
using Microsoft.Extensions.Logging;

namespace AutoHttps.Hosting;

/// <summary>
/// Delivers certificate change and failure notifications to the registered listeners. A listener
/// that throws is logged and skipped, so one bad listener cannot stop the others or the renewal
/// loop that called in.
/// </summary>
internal sealed class CertificateEventPublisher
{
    private readonly IReadOnlyList<IAutoHttpsCertificateListener> _listeners;
    private readonly ILogger<CertificateEventPublisher> _logger;

    public CertificateEventPublisher(
        IEnumerable<IAutoHttpsCertificateListener> listeners,
        ILogger<CertificateEventPublisher> logger)
    {
        _listeners = [.. listeners];
        _logger = logger;
    }

    public async Task NotifyChangedAsync(CertificateChangedContext context, CancellationToken cancellationToken)
    {
        foreach (IAutoHttpsCertificateListener listener in _listeners)
        {
            try
            {
                await listener.OnCertificateChangedAsync(context, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Log.CertificateListenerFailed(_logger, listener.GetType().Name, ex);
            }
        }
    }

    public async Task NotifyFailedAsync(CertificateFailedContext context, CancellationToken cancellationToken)
    {
        foreach (IAutoHttpsCertificateListener listener in _listeners)
        {
            try
            {
                await listener.OnCertificateFailedAsync(context, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Log.CertificateListenerFailed(_logger, listener.GetType().Name, ex);
            }
        }
    }
}
