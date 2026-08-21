using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace AutoHttps.IntegrationTests;

/// <summary>
/// Keeps the application's log so that a test which times out waiting for a certificate can report
/// why the order failed instead of only that it did.
/// </summary>
internal sealed class LogCapture : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _entries = new();
    private readonly ConcurrentDictionary<int, int> _eventCounts = new();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, this);

    public int CountOf(int eventId) => _eventCounts.TryGetValue(eventId, out int count) ? count : 0;

    public IReadOnlyList<string> Entries => _entries.ToArray();

    public string Describe(int limit = 30) =>
        string.Join(Environment.NewLine, _entries.Reverse().Take(limit).Reverse());

    public void Dispose()
    {
    }

    private void Record(string entry, int eventId)
    {
        _entries.Enqueue(entry);
        _eventCounts.AddOrUpdate(eventId, 1, static (_, existing) => existing + 1);

        while (_entries.Count > 300 && _entries.TryDequeue(out _))
        {
        }
    }

    private sealed class CapturingLogger : ILogger
    {
        private readonly string _category;
        private readonly LogCapture _owner;

        public CapturingLogger(string category, LogCapture owner)
        {
            _category = category;
            _owner = owner;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            string message = $"{logLevel} {_category}[{eventId.Id}] {formatter(state, exception)}";
            if (exception is not null)
            {
                message += Environment.NewLine + "    " + exception.GetType().Name + ": " + exception.Message;

                if (exception.InnerException is { } inner)
                {
                    message += Environment.NewLine + "    caused by " + inner.GetType().Name + ": " + inner.Message;
                }
            }

            _owner.Record(message, eventId.Id);
        }
    }
}
