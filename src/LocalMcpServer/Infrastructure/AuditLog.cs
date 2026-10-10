using Microsoft.Extensions.Logging;

namespace LocalMcpServer.Infrastructure;

public sealed record AuditEntry(DateTimeOffset Timestamp, string Category, string Message, bool Denied)
{
    public override string ToString() =>
        $"{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{(Denied ? "DENY" : " OK ")}] {Category}: {Message}";
}

/// <summary>Append-only audit trail of every tool call and every denied request.</summary>
public sealed class AuditLog
{
    private const int RecentCapacity = 1000;
    private readonly object _gate = new();
    private readonly Queue<AuditEntry> _recent = new();
    private readonly string? _directory;

    public AuditLog(string? directory)
    {
        _directory = directory;
        if (directory is not null)
        {
            Directory.CreateDirectory(directory);
        }
    }

    public event Action<AuditEntry>? EntryWritten;

    public string? LogDirectory => _directory;

    public void Write(string category, string message, bool denied = false)
    {
        var entry = new AuditEntry(DateTimeOffset.Now, category, message, denied);
        lock (_gate)
        {
            _recent.Enqueue(entry);
            while (_recent.Count > RecentCapacity)
            {
                _recent.Dequeue();
            }

            if (_directory is not null)
            {
                try
                {
                    File.AppendAllText(
                        Path.Combine(_directory, $"audit-{entry.Timestamp:yyyyMMdd}.log"),
                        entry + Environment.NewLine);
                }
                catch (IOException)
                {
                    // Another process (stdio + tray instance) may hold the file briefly; the in-memory log still has it.
                }
            }
        }

        EntryWritten?.Invoke(entry);
    }

    public IReadOnlyList<AuditEntry> Snapshot()
    {
        lock (_gate)
        {
            return _recent.ToArray();
        }
    }
}

/// <summary>Routes framework warnings/errors (Kestrel, MCP SDK) into the audit log.</summary>
public sealed class AuditLoggerProvider(AuditLog audit, LogLevel minimumLevel) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new AuditLogger(audit, categoryName, minimumLevel);

    public void Dispose()
    {
    }

    private sealed class AuditLogger(AuditLog audit, string category, LogLevel minimumLevel) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= minimumLevel && logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var shortCategory = category.Contains('.') ? category[(category.LastIndexOf('.') + 1)..] : category;
            var message = formatter(state, exception);
            if (exception is not null)
            {
                message += $" ({exception.GetType().Name}: {exception.Message})";
            }

            audit.Write($"{logLevel}/{shortCategory}", message, denied: logLevel >= LogLevel.Error);
        }
    }
}
