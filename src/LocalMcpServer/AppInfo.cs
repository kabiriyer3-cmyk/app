using System.Reflection;
using System.Security.Principal;

namespace LocalMcpServer;

internal static class AppInfo
{
    public const string ProductName = "Local MCP Server";
    public const string ServerName = "local-mcp-server";

    public static readonly DateTimeOffset StartedAt = DateTimeOffset.Now;

    public static string Version { get; } = ResolveVersion();

    private static string ResolveVersion()
    {
        var assembly = typeof(AppInfo).Assembly;
        var info = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrWhiteSpace(info))
        {
            return assembly.GetName().Version?.ToString() ?? "0.0.0";
        }

        var plus = info.IndexOf('+');
        return plus > 0 ? info[..plus] : info;
    }

    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
