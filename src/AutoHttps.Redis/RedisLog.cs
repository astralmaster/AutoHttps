using System;
using Microsoft.Extensions.Logging;

namespace AutoHttps.Redis;

internal static partial class RedisLog
{
    [LoggerMessage(
        EventId = 160,
        Level = LogLevel.Warning,
        Message = "The Redis lock {Key} expired or was taken by another instance while this one held it, so another " +
                  "instance may be ordering the same certificate. This instance stops renewing it. A Redis outage " +
                  "longer than LockLease ({Lease}), an eviction or a failover without persistence causes this.")]
    public static partial void LockLeaseLost(ILogger logger, string key, TimeSpan lease);
}
