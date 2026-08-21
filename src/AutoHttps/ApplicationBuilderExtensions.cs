using System;
using AutoHttps.Challenges;
using Microsoft.AspNetCore.Builder;

namespace AutoHttps;

/// <summary>
/// Places the ACME challenge responder in an application's request pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Serves <c>http-01</c> challenge responses from <c>/.well-known/acme-challenge</c>.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder, for chaining.</returns>
    /// <remarks>
    /// AutoHttps already inserts this at the front of the pipeline. Call it explicitly only after
    /// setting <see cref="AutoHttpsOptions.HandleHttp01Requests"/> to <see langword="false"/>, and
    /// place it before any middleware that redirects or authenticates requests.
    /// </remarks>
    public static IApplicationBuilder UseAutoHttpsChallenges(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<Http01ChallengeMiddleware>();
    }
}
