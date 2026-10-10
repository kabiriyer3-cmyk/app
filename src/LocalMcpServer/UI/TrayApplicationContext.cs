using LocalMcpServer.Configuration;
using LocalMcpServer.Hosting;
using LocalMcpServer.Infrastructure;
using LocalMcpServer.Security;

namespace LocalMcpServer.UI;

/// <summary>Owns the tray icon, the HTTP transport lifecycle and the dashboard window.</summary>
internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _tray;
    private readonly HttpServerHost _http = new();
    private readonly string? _configPath;
    private MainForm? _dashboard;

    public TrayApplicationContext(ServerOptions options, AuditLog audit, string? configPath)
    {
        Options = options;
        Audit = audit;
        _configPath = configPath;
        AccessToken = SettingsStore.GetOrCreateAccessToken();

        var menu = new ContextMenuStrip();
        menu.Items.Add("Open dashboard", null, (_, _) => ShowDashboard());
        menu.Items.Add("Copy access token", null, (_, _) => Clipboard.SetText(AccessToken));
        menu.Items.Add("Restart server", null, async (_, _) => await RestartAsync());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, async (_, _) => await ExitAsync());

        _tray = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = AppInfo.ProductName,
            ContextMenuStrip = menu,
            Visible = true,
        };
        _tray.DoubleClick += (_, _) => ShowDashboard();

        _ = RestartAsync();
    }

    public ServerOptions Options { get; private set; }

    public AuditLog Audit { get; }

    public string AccessToken { get; private set; }

    public string Status { get; private set; } = "Starting…";

    public string? Endpoint => _http.Endpoint;

    public event Action? StatusChanged;

    public async Task RestartAsync()
    {
        await _http.StopAsync();

        var guard = new WorkspaceGuard(Options);
        foreach (var error in guard.ConfigurationErrors)
        {
            Audit.Write("config", error, denied: true);
        }

        if (!Options.EnableHttp)
        {
            SetStatus($"HTTP disabled. stdio available via --stdio. {guard.Roots.Count} workspace(s).");
            return;
        }

        try
        {
            await _http.StartAsync(Options, AccessToken, Audit);
            SetStatus($"Listening on {_http.Endpoint} · {guard.Roots.Count} workspace(s)");
        }
        catch (Exception ex)
        {
            Audit.Write("server", $"Failed to start HTTP transport: {ex.Message}", denied: true);
            SetStatus($"Failed to start: {ex.Message}");
            _tray.ShowBalloonTip(5000, AppInfo.ProductName, $"Server failed to start: {ex.Message}", ToolTipIcon.Error);
        }
    }

    public async Task ApplySettingsAsync(ServerOptions options)
    {
        SettingsStore.Save(options, _configPath);
        Options = options;
        Audit.Write("config", "Settings saved; restarting transport.");
        await RestartAsync();
    }

    public async Task RotateTokenAsync()
    {
        AccessToken = SettingsStore.RotateAccessToken();
        Audit.Write("config", "Access token rotated. Update your MCP client configuration.");
        await RestartAsync();
    }

    private void ShowDashboard()
    {
        if (_dashboard is null || _dashboard.IsDisposed)
        {
            _dashboard = new MainForm(this);
        }

        _dashboard.Show();
        _dashboard.WindowState = FormWindowState.Normal;
        _dashboard.Activate();
    }

    private void SetStatus(string status)
    {
        Status = status;
        var tooltip = $"{AppInfo.ProductName}: {status}";
        _tray.Text = tooltip.Length > 127 ? tooltip[..127] : tooltip;
        StatusChanged?.Invoke();
    }

    private async Task ExitAsync()
    {
        await _http.StopAsync();
        _tray.Visible = false;
        _dashboard?.ForceClose();
        ExitThread();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _tray.Dispose();
            _dashboard?.Dispose();
        }

        base.Dispose(disposing);
    }
}
