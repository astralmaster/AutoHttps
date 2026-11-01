using System;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Hosting;
using Xunit;

namespace AutoHttps.Tests;

/// <summary>
/// The hand-off between RenewAsync and the renewal loop. Every request has to end, met or failed, or a
/// caller such as an admin endpoint waits forever.
/// </summary>
public sealed class RenewalRequestsTests
{
    [Fact]
    public async Task ARequestIsMetByAnyOtherCertificateBeingPublished()
    {
        var requests = new RenewalRequests();
        Task request = requests.RequestAsync("OLD", CancellationToken.None);

        requests.Published("OLD");
        Assert.False(request.IsCompleted);

        requests.Published("NEW");
        await request.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task AFailedAttemptEndsEveryPendingRequest()
    {
        var requests = new RenewalRequests();
        Task first = requests.RequestAsync("OLD", CancellationToken.None);
        Task second = requests.RequestAsync(null, CancellationToken.None);

        requests.Failed(new InvalidOperationException("validation failed"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => first);
        await Assert.ThrowsAsync<InvalidOperationException>(() => second);
        Assert.False(requests.HasPending);
    }

    [Fact]
    public async Task ClosingEndsPendingRequestsAndRefusesLaterOnes()
    {
        var requests = new RenewalRequests();
        Task pending = requests.RequestAsync("OLD", CancellationToken.None);

        requests.Close(new OperationCanceledException("stopping"));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => requests.RequestAsync("OLD", CancellationToken.None));
    }

    [Fact]
    public async Task TheFirstReasonForClosingIsKept()
    {
        // The loop closes with the reason nothing is ordered (development mode), and again on the way
        // out whatever happened. The second call must not replace the first reason.
        var requests = new RenewalRequests();

        requests.Close(new InvalidOperationException("a development certificate is being served"));
        requests.Close(new OperationCanceledException("stopping"));

        InvalidOperationException refused = await Assert.ThrowsAsync<InvalidOperationException>(
            () => requests.RequestAsync(null, CancellationToken.None));
        Assert.Contains("development", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CancellingTheCallerLeavesTheRequestStanding()
    {
        var requests = new RenewalRequests();
        using var caller = new CancellationTokenSource();

        Task request = requests.RequestAsync("OLD", caller.Token);
        await caller.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
        Assert.True(requests.HasPending);
        Assert.True(requests.IsRequested("OLD"));
    }
}
