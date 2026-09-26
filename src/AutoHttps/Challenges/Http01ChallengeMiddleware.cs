using System;
using System.Text;
using System.Threading.Tasks;
using AutoHttps.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AutoHttps.Challenges;

internal sealed class Http01ChallengeMiddleware
{
    private static readonly PathString ChallengePrefix = new("/.well-known/acme-challenge");

    private readonly RequestDelegate _next;
    private readonly IHttp01ChallengeStore _store;
    private readonly Http01RequestProbe _probe;
    private readonly ILogger<Http01ChallengeMiddleware> _logger;

    public Http01ChallengeMiddleware(
        RequestDelegate next,
        IHttp01ChallengeStore store,
        Http01RequestProbe probe,
        ILogger<Http01ChallengeMiddleware> logger)
    {
        _next = next;
        _store = store;
        _probe = probe;
        _logger = logger;
    }

    public Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments(ChallengePrefix, out PathString token))
        {
            return _next(context);
        }

        string candidate = token.Value?.TrimStart('/') ?? string.Empty;
        if (candidate.Length == 0 || candidate.Contains('/', StringComparison.Ordinal))
        {
            return _next(context);
        }

        // Reading the store is the only part that can be asynchronous, and it only happens for the
        // challenge path, so ordinary traffic stays on the synchronous path through this middleware.
        return ServeAsync(context, candidate);
    }

    private async Task ServeAsync(HttpContext context, string token)
    {
        string? keyAuthorization;
        try
        {
            keyAuthorization = await _store.GetAsync(token, context.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A shared store that cannot be reached must not turn into a 500 with nothing to explain
            // it. The authority sees an unanswered challenge either way; the log says why.
            Log.Http01ChallengeStoreUnavailable(_logger, token, ex);
            await _next(context);
            return;
        }

        if (keyAuthorization is null)
        {
            await _next(context);
            return;
        }

        _probe.MarkServed(token);
        Log.Http01ChallengeAnswered(_logger, token);

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/octet-stream";
        context.Response.ContentLength = Encoding.ASCII.GetByteCount(keyAuthorization);

        await context.Response.WriteAsync(keyAuthorization, Encoding.ASCII, context.RequestAborted);
    }
}
