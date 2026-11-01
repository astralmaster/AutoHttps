using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AutoHttps.Hosting;

/// <summary>
/// Requests for a new certificate made through <see cref="IAutoHttpsCertificateManager.RenewAsync"/>,
/// passed from the caller to the renewal loop. A request names the certificate being served when it
/// was made, and is met by any other certificate being published, so requests made together share one
/// order and one published by another instance meets them too. Every request ends: met, failed with
/// the attempt's exception, or failed when the loop cannot take requests at all.
/// </summary>
internal sealed class RenewalRequests
{
    private readonly object _gate = new();
    private readonly List<Request> _pending = [];
    private TaskCompletionSource _signal = NewSignal();
    private Exception? _closed;

    /// <summary>Completes when a request arrives, so a loop waiting out its schedule wakes up.</summary>
    public Task WhenRequested
    {
        get
        {
            lock (_gate)
            {
                return _signal.Task;
            }
        }
    }

    public bool HasPending
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count > 0;
            }
        }
    }

    /// <param name="replacing">The thumbprint of the certificate served when the request was made, or null if none was.</param>
    /// <param name="cancellationToken">Stops the caller waiting. The request itself stands.</param>
    public Task RequestAsync(string? replacing, CancellationToken cancellationToken)
    {
        var request = new Request(replacing);

        lock (_gate)
        {
            if (_closed is not null)
            {
                return Task.FromException(_closed);
            }

            _pending.Add(request);
            _signal.TrySetResult();
        }

        return request.Completion.Task.WaitAsync(cancellationToken);
    }

    /// <summary>Whether a pending request asks for this certificate to be replaced.</summary>
    public bool IsRequested(string thumbprint)
    {
        lock (_gate)
        {
            foreach (Request request in _pending)
            {
                if (string.Equals(request.Replacing, thumbprint, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>Meets every request for a certificate other than the one now published.</summary>
    public void Published(string thumbprint)
    {
        lock (_gate)
        {
            _pending.RemoveAll(request =>
            {
                if (string.Equals(request.Replacing, thumbprint, StringComparison.Ordinal))
                {
                    return false;
                }

                request.Completion.TrySetResult();
                return true;
            });
        }
    }

    /// <summary>Ends every pending request with the reason the attempt failed.</summary>
    public void Failed(Exception exception)
    {
        lock (_gate)
        {
            foreach (Request request in _pending)
            {
                request.Completion.TrySetException(exception);
            }

            _pending.Clear();
        }
    }

    /// <summary>
    /// Ends every pending request and refuses later ones with <paramref name="reason"/>, for when the
    /// loop will not act on them: nothing is ordered in this process, or the host is stopping. The
    /// first reason is kept, because the loop also closes on the way out whatever stopped it.
    /// </summary>
    public void Close(Exception reason)
    {
        lock (_gate)
        {
            _closed ??= reason;

            foreach (Request request in _pending)
            {
                request.Completion.TrySetException(_closed);
            }

            _pending.Clear();
        }
    }

    /// <summary>Re-arms <see cref="WhenRequested"/> once the loop has seen the requests so far.</summary>
    public void Acknowledge()
    {
        lock (_gate)
        {
            if (_signal.Task.IsCompleted)
            {
                _signal = NewSignal();
            }
        }
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private sealed class Request(string? replacing)
    {
        public string? Replacing { get; } = replacing;

        public TaskCompletionSource Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
