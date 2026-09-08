using System;
using System.Threading.Tasks;
using StackExchange.Redis;
using Xunit;

namespace AutoHttps.Redis.Tests;

public sealed class RedisFixture : IAsyncLifetime
{
    private readonly string _configuration =
        (Environment.GetEnvironmentVariable("AUTOHTTPS_REDIS") ?? "localhost:6379") + ",abortConnect=false,connectTimeout=3000";

    public IConnectionMultiplexer Multiplexer { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        try
        {
            Multiplexer = await ConnectionMultiplexer.ConnectAsync(_configuration);
        }
        catch (RedisConnectionException ex)
        {
            throw NotReachable(ex);
        }

        if (!Multiplexer.IsConnected)
        {
            throw NotReachable(null);
        }
    }

    public Task DisposeAsync()
    {
        Multiplexer?.Dispose();
        return Task.CompletedTask;
    }

    private static InvalidOperationException NotReachable(Exception? inner) => new(
        "Redis is not reachable. Start it with:" + Environment.NewLine +
        "    docker compose -f test/redis/docker-compose.yml up -d",
        inner);
}

[CollectionDefinition(Name)]
public sealed class RedisCollection : ICollectionFixture<RedisFixture>
{
    public const string Name = "redis";
}
