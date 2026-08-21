using System;
using AutoHttps.Challenges;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;

namespace AutoHttps.Hosting;

internal sealed class Http01StartupFilter : IStartupFilter
{
    private readonly AutoHttpsOptions _options;

    public Http01StartupFilter(IOptions<AutoHttpsOptions> options) => _options = options.Value;

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        // The challenge response has to be served before anything that could redirect, authenticate
        // or rewrite the request, so it is placed at the very front of the pipeline.
        if (_options.HandleHttp01Requests)
        {
            app.UseMiddleware<Http01ChallengeMiddleware>();
        }

        next(app);
    };
}
