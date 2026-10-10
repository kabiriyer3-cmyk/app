using System.Net;
using System.Net.Sockets;
using LocalMcpServer.Configuration;
using LocalMcpServer.Infrastructure;
using LocalMcpServer.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.AspNetCore;

namespace LocalMcpServer.Hosting;

/// <summary>
/// Streamable HTTP transport bound exclusively to the loopback interface, used while the tray app runs.
/// </summary>
internal sealed class HttpServerHost : IAsyncDisposable
{
    private WebApplication? _app;

    public bool IsRunning => _app is not null;

    public string? Endpoint { get; private set; }

    public async Task StartAsync(ServerOptions options, string accessToken, AuditLog audit)
    {
        if (_app is not null)
        {
            throw new InvalidOperationException("Server already running.");
        }

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = AppContext.BaseDirectory,
            Args = [],
        });

        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(new AuditLoggerProvider(audit, LogLevel.Warning));

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = (options.MaxWriteBytes * 2) + (1024 * 1024); // JSON escaping overhead
            kestrel.Listen(IPAddress.Loopback, options.HttpPort);
            if (Socket.OSSupportsIPv6)
            {
                kestrel.Listen(IPAddress.IPv6Loopback, options.HttpPort);
            }
        });

        builder.Services.AddSingleton(new HttpSecurityContext(accessToken, options.HttpPort));
        builder.Services
            .AddLocalMcpServer(options, audit)
            .WithHttpTransport(transport =>
            {
                // Hybrid mode: clients still using the initialize handshake (2025-xx revisions) get a real session
                // with Mcp-Session-Id and the GET stream; 2026-07-28+ clients are served statelessly.
                transport.SessionMode = HttpServerSessionMode.StatefulForInitializeClients;
            });

        var app = builder.Build();
        app.UseMiddleware<LocalRequestGuard>();
        app.MapGet("/healthz", () => Results.Json(new { status = "ok", server = AppInfo.ServerName, version = AppInfo.Version }));
        app.MapMcp("/mcp");

        await app.StartAsync();
        _app = app;
        Endpoint = $"http://127.0.0.1:{options.HttpPort}/mcp";
        audit.Write("server", $"HTTP transport listening on {Endpoint}");
    }

    public async Task StopAsync()
    {
        if (_app is null)
        {
            return;
        }

        var app = _app;
        _app = null;
        Endpoint = null;
        await app.StopAsync(TimeSpan.FromSeconds(5));
        await app.DisposeAsync();
    }

    public async ValueTask DisposeAsync() => await StopAsync();
}
