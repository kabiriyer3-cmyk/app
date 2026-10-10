using LocalMcpServer.Configuration;
using LocalMcpServer.Hosting;
using LocalMcpServer.Infrastructure;
using LocalMcpServer.UI;

namespace LocalMcpServer;

internal static class Program
{
    /// <summary>
    /// LocalMcpServer.exe                 -> tray app + dashboard, Streamable HTTP on 127.0.0.1 (token protected)
    /// LocalMcpServer.exe --stdio         -> headless stdio transport, launched by the MCP client
    /// --config "C:\path\settings.json"   -> use an explicit settings file (portable mode / testing)
    /// </summary>
    [STAThread]
    private static int Main(string[] args)
    {
        var stdio = args.Any(a => a.Equals("--stdio", StringComparison.OrdinalIgnoreCase));
        var configPath = GetArgValue(args, "--config");

        ServerOptions options;
        try
        {
            options = SettingsStore.Load(configPath);
        }
        catch (Exception ex)
        {
            return Fail(stdio, $"Could not load settings: {ex.Message}", 2);
        }

        var audit = new AuditLog(SettingsStore.LogDirectory);

        if (options.RefuseElevated && AppInfo.IsElevated())
        {
            audit.Write("server", "Refused to start from an elevated process.", denied: true);
            return Fail(stdio, "Local MCP Server refuses to run as Administrator. Start it from a normal (non-elevated) session.", 3);
        }

        if (stdio)
        {
            return StdioServerHost.RunAsync(options, audit).GetAwaiter().GetResult();
        }

        using var singleInstance = new Mutex(initiallyOwned: true, @"Local\LocalMcpServer.Tray", out var isFirstInstance);
        if (!isFirstInstance)
        {
            MessageBox.Show("Local MCP Server is already running in the system tray.", AppInfo.ProductName,
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayApplicationContext(options, audit, configPath));
        return 0;
    }

    private static string? GetArgValue(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }

        return null;
    }

    private static int Fail(bool stdio, string message, int code)
    {
        if (stdio)
        {
            Console.Error.WriteLine(message);
        }
        else
        {
            MessageBox.Show(message, AppInfo.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        return code;
    }
}
