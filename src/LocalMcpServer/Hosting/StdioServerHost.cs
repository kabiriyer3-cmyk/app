using LocalMcpServer.Configuration;
using LocalMcpServer.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LocalMcpServer.Hosting;

/// <summary>
/// stdio transport: the MCP client (Claude Desktop, Cursor, VS Code...) launches "LocalMcpServer.exe --stdio"
/// and talks JSON-RPC over stdin/stdout. No network socket is opened in this mode.
/// </summary>
internal static class StdioServerHost
{
    public static async Task<int> RunAsync(ServerOptions options, AuditLog audit)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            ContentRootPath = AppContext.BaseDirectory,
            DisableDefaults = true, // no default console logger on stdout: stdout belongs to JSON-RPC
        });

        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        builder.Logging.AddProvider(new AuditLoggerProvider(audit, LogLevel.Warning));

        builder.Services
            .AddLocalMcpServer(options, audit)
            .WithStdioServerTransport();

        using var host = builder.Build();
        audit.Write("server", $"stdio transport started (v{AppInfo.Version})");
        await host.RunAsync();
        audit.Write("server", "stdio transport stopped");
        return 0;
    }
}
