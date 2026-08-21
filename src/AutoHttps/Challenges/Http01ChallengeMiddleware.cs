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
    private readonly Http01ChallengeStore _store;
    private readonly ILogger<Http01ChallengeMiddleware> _logger;

    public Http01ChallengeMiddleware(RequestDelegate next, Http01ChallengeStore store, ILogger<Http01ChallengeMiddleware> logger)
    {
        _next = next;
        _store = store;
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

        if (!_store.TryGet(candidate, out string? keyAuthorization))
        {
            return _next(context);
        }

        Log.Http01ChallengeAnswered(_logger, candidate);

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/octet-stream";
        context.Response.ContentLength = Encoding.ASCII.GetByteCount(keyAuthorization);

        return context.Response.WriteAsync(keyAuthorization, Encoding.ASCII, context.RequestAborted);
    }
}
