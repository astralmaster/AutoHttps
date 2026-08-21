using System;
using System.Threading;
using System.Threading.Tasks;
using AutoHttps.Acme;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AutoHttps.Challenges;

internal sealed class Dns01ChallengeHandler : IChallengeHandler
{
    private const string RecordPrefix = "_acme-challenge.";

    private readonly IDnsChallengeProvider? _provider;
    private readonly TimeSpan _propagationDelay;
    private readonly TimeProvider _time;

    public Dns01ChallengeHandler(IOptions<AutoHttpsOptions> options, TimeProvider time, IServiceProvider services)
        : this(
            services.GetService<IDnsChallengeProvider>() ?? options.Value.DnsChallengeProvider,
            options.Value.DnsPropagationDelay,
            time)
    {
    }

    public Dns01ChallengeHandler(IDnsChallengeProvider? provider, TimeSpan propagationDelay, TimeProvider time)
    {
        _provider = provider;
        _propagationDelay = propagationDelay;
        _time = time;
    }

    public string ChallengeType => ChallengeTypes.Dns01;

    public bool CanHandle(string identifierType) =>
        _provider is not null && identifierType == AcmeIdentifierTypes.Dns;

    public async Task PrepareAsync(ChallengeContext context, CancellationToken cancellationToken)
    {
        IDnsChallengeProvider provider = RequireProvider();
        await provider.CreateTxtRecordAsync(GetRecordName(context.Identifier), context.DnsRecordValue, cancellationToken);

        if (_propagationDelay > TimeSpan.Zero)
        {
            await Task.Delay(_propagationDelay, _time, cancellationToken);
        }
    }

    public Task CleanupAsync(ChallengeContext context, CancellationToken cancellationToken) =>
        RequireProvider().DeleteTxtRecordAsync(GetRecordName(context.Identifier), context.DnsRecordValue, cancellationToken);

    public string? DescribeFailure(ChallengeContext context, AcmeException failure) => null;

    internal static string GetRecordName(string identifier) => RecordPrefix + identifier.TrimStart('*', '.');

    private IDnsChallengeProvider RequireProvider() =>
        _provider ?? throw new InvalidOperationException("No DNS challenge provider is configured.");
}
