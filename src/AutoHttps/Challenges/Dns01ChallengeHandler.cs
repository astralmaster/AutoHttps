using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using AutoHttps.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AutoHttps.Challenges;

internal sealed class Dns01ChallengeHandler : IChallengeHandler
{
    private readonly IDnsChallengeProvider? _provider;
    private readonly TimeSpan _propagationDelay;
    private readonly TimeProvider _time;
    private readonly DnsPropagationChecker? _checker;
    private readonly IReadOnlyDictionary<string, string> _aliases;
    private readonly ILogger _logger;

    public Dns01ChallengeHandler(IOptions<AutoHttpsOptions> options, TimeProvider time, IServiceProvider services)
        : this(
            services.GetService<IDnsChallengeProvider>() ?? options.Value.DnsChallengeProvider,
            options.Value.DnsPropagationDelay,
            time,
            options.Value.DnsChallengeAliases,
            services.GetService<DnsPropagationChecker>(),
            services.GetService<ILogger<Dns01ChallengeHandler>>())
    {
    }

    public Dns01ChallengeHandler(
        IDnsChallengeProvider? provider,
        TimeSpan propagationDelay,
        TimeProvider time,
        IDictionary<string, string>? aliases = null,
        DnsPropagationChecker? checker = null,
        ILogger? logger = null)
    {
        _provider = provider;
        _propagationDelay = propagationDelay;
        _time = time;
        _checker = checker;
        _aliases = DnsChallengeNames.Normalize(aliases ?? new Dictionary<string, string>());
        _logger = logger ?? NullLogger.Instance;
    }

    public string ChallengeType => ChallengeTypes.Dns01;

    public bool CanHandle(string identifierType) =>
        _provider is not null && identifierType == AcmeIdentifierTypes.Dns;

    public async Task PrepareAsync(ChallengeContext context, CancellationToken cancellationToken)
    {
        IDnsChallengeProvider provider = RequireProvider();
        string challengeName = GetRecordName(context.Identifier);
        string recordName = GetTargetName(context.Identifier);

        if (!string.Equals(recordName, challengeName, StringComparison.Ordinal))
        {
            Log.ChallengeRecordDelegated(_logger, context.Identifier, recordName, challengeName);
        }

        await provider.CreateTxtRecordAsync(recordName, context.DnsRecordValue, cancellationToken);

        if (_checker is { IsEnabled: true })
        {
            // The name the authority reads, not the alias: through a recursive resolver it shows the record
            // only by way of the CNAME, so a missing CNAME is seen here rather than as a failed validation.
            await _checker.WaitForRecordAsync(challengeName, context.DnsRecordValue, cancellationToken);
        }
        else if (_propagationDelay > TimeSpan.Zero)
        {
            await Task.Delay(_propagationDelay, _time, cancellationToken);
        }
    }

    public Task CleanupAsync(ChallengeContext context, CancellationToken cancellationToken) =>
        RequireProvider().DeleteTxtRecordAsync(GetTargetName(context.Identifier), context.DnsRecordValue, cancellationToken);

    public string? DescribeFailure(ChallengeContext context, AcmeException failure) => null;

    internal static string GetRecordName(string identifier) => DnsChallengeNames.ForIdentifier(identifier);

    private string GetTargetName(string identifier) =>
        _aliases.TryGetValue(DnsChallengeNames.BaseName(identifier), out string? alias) ? alias : GetRecordName(identifier);

    private IDnsChallengeProvider RequireProvider() =>
        _provider ?? throw new InvalidOperationException("No DNS challenge provider is configured.");
}
