using LocalMcpServer.Configuration;
using LocalMcpServer.Infrastructure;
using LocalMcpServer.Security;
using LocalMcpServer.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace LocalMcpServer.Hosting;

internal static class McpServiceRegistration
{
    /// <summary>Registers the MCP server and the explicit tool allow-list shared by the stdio and HTTP transports.</summary>
    public static IMcpServerBuilder AddLocalMcpServer(this IServiceCollection services, ServerOptions options, AuditLog audit)
    {
        services.AddSingleton(options);
        services.AddSingleton(audit);
        services.AddSingleton<WorkspaceGuard>();

        return services
            .AddMcpServer(server =>
            {
                server.ServerInfo = new ModelContextProtocol.Protocol.Implementation
                {
                    Name = AppInfo.ServerName,
                    Version = AppInfo.Version,
                };
            })
            // Explicit registration (no assembly scanning): only these types are ever exposed as tools.
            .WithTools<FileSystemTools>()
            .WithTools<SystemInfoTools>()
            .WithTools<ModdingTools>();
    }
}
