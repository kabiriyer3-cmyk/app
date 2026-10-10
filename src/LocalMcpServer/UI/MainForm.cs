using System.Diagnostics;
using System.Text.Json;
using LocalMcpServer.Configuration;
using LocalMcpServer.Infrastructure;
using LocalMcpServer.Security;

namespace LocalMcpServer.UI;

/// <summary>Dashboard: workspace permissions, transport settings, client config and the live audit log.</summary>
internal sealed class MainForm : Form
{
    private readonly TrayApplicationContext _host;
    private readonly Label _status = new() { AutoSize = true, Padding = new Padding(0, 4, 0, 8) };
    private readonly ListView _workspaces = new() { View = View.Details, FullRowSelect = true, MultiSelect = false, Dock = DockStyle.Fill, HideSelection = false };
    private readonly CheckBox _enableHttp = new() { Text = "Enable HTTP transport (127.0.0.1 only, token required)", AutoSize = true };
    private readonly CheckBox _allowDelete = new() { Text = "Allow delete (Recycle Bin)", AutoSize = true };
    private readonly NumericUpDown _port = new() { Minimum = 1024, Maximum = 65535, Width = 80 };
    private readonly TextBox _allowedHosts = new() { Width = 320, PlaceholderText = "*.lhr.life, *.trycloudflare.com" };
    private readonly TextBox _log = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill };
    private ServerOptions _draft;
    private bool _forceClose;

    public MainForm(TrayApplicationContext host)
    {
        _host = host;
        _draft = SettingsStore.Clone(host.Options);

        Text = $"{AppInfo.ProductName} {AppInfo.Version}";
        Icon = SystemIcons.Shield;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(820, 600);
        Size = new Size(980, 720);
        _status.Font = new Font(Font, FontStyle.Bold);
        _log.Font = new Font(FontFamily.GenericMonospace, 9f);

        _workspaces.Columns.Add("Name", 160);
        _workspaces.Columns.Add("Access", 90);
        _workspaces.Columns.Add("Path", 600);

        var workspaceButtons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        workspaceButtons.Controls.Add(MakeButton("Add folder…", (_, _) => AddWorkspace()));
        workspaceButtons.Controls.Add(MakeButton("Remove", (_, _) => RemoveWorkspace()));
        workspaceButtons.Controls.Add(MakeButton("Toggle read/write", (_, _) => ToggleAccess()));

        var workspaceLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        workspaceLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        workspaceLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        workspaceLayout.Controls.Add(_workspaces, 0, 0);
        workspaceLayout.Controls.Add(workspaceButtons, 0, 1);
        var workspaceGroup = new GroupBox { Text = "Workspaces (the only folders AI clients can see)", Dock = DockStyle.Fill, Padding = new Padding(8) };
        workspaceGroup.Controls.Add(workspaceLayout);

        var settings = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        settings.Controls.Add(_enableHttp);
        settings.Controls.Add(new Label { Text = "Port:", AutoSize = true, Padding = new Padding(12, 6, 0, 0) });
        settings.Controls.Add(_port);
        settings.Controls.Add(_allowDelete);
        settings.Controls.Add(new Label { Text = "Tunnel hosts:", AutoSize = true, Padding = new Padding(12, 6, 0, 0) });
        settings.Controls.Add(_allowedHosts);

        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true };
        actions.Controls.Add(MakeButton("Save && restart", async (_, _) => await SaveAsync()));
        actions.Controls.Add(MakeButton("Copy token", (_, _) => Clipboard.SetText(_host.AccessToken)));
        actions.Controls.Add(MakeButton("Rotate token", async (_, _) => await RotateTokenAsync()));
        actions.Controls.Add(MakeButton("Copy HTTP client config", (_, _) => CopyClientConfig(http: true)));
        actions.Controls.Add(MakeButton("Copy stdio client config", (_, _) => CopyClientConfig(http: false)));
        actions.Controls.Add(MakeButton("Open logs folder", (_, _) => OpenLogs()));

        var logGroup = new GroupBox { Text = "Audit log", Dock = DockStyle.Fill, Padding = new Padding(8) };
        logGroup.Controls.Add(_log);

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(10) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
        root.Controls.Add(_status, 0, 0);
        root.Controls.Add(workspaceGroup, 0, 1);
        root.Controls.Add(settings, 0, 2);
        root.Controls.Add(actions, 0, 3);
        root.Controls.Add(logGroup, 0, 4);
        Controls.Add(root);

        LoadDraft();
        foreach (var entry in _host.Audit.Snapshot().TakeLast(300))
        {
            _log.AppendText(entry + Environment.NewLine);
        }

        _host.Audit.EntryWritten += OnAuditEntry;
        _host.StatusChanged += OnStatusChanged;
        OnStatusChanged();
    }

    public void ForceClose()
    {
        _forceClose = true;
        Close();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_forceClose && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true; // Closing the window keeps the server running in the tray.
            Hide();
            return;
        }

        _host.Audit.EntryWritten -= OnAuditEntry;
        _host.StatusChanged -= OnStatusChanged;
        base.OnFormClosing(e);
    }

    private static Button MakeButton(string text, EventHandler onClick)
    {
        var button = new Button { Text = text, AutoSize = true, Padding = new Padding(6, 2, 6, 2) };
        button.Click += onClick;
        return button;
    }

    private void LoadDraft()
    {
        _enableHttp.Checked = _draft.EnableHttp;
        _allowDelete.Checked = _draft.AllowDelete;
        _port.Value = Math.Clamp(_draft.HttpPort, (int)_port.Minimum, (int)_port.Maximum);
        _allowedHosts.Text = string.Join(", ", _draft.AllowedHosts);
        RefreshWorkspaces();
    }

    private void RefreshWorkspaces()
    {
        _workspaces.BeginUpdate();
        _workspaces.Items.Clear();
        foreach (var ws in _draft.Workspaces)
        {
            var item = new ListViewItem(new[] { ws.Name, ws.Access.ToString(), ws.Path }) { Tag = ws };
            if (ws.Access == WorkspaceAccess.ReadWrite)
            {
                item.ForeColor = Color.DarkOrange;
            }

            _workspaces.Items.Add(item);
        }

        _workspaces.EndUpdate();
    }

    private WorkspaceRootOptions? Selected =>
        _workspaces.SelectedItems.Count == 1 ? _workspaces.SelectedItems[0].Tag as WorkspaceRootOptions : null;

    private void AddWorkspace()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Choose a folder the MCP server may access (read-only by default)",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        string full;
        try
        {
            full = WorkspaceGuard.NormalizeDirectory(dialog.SelectedPath);
        }
        catch (ArgumentException ex)
        {
            MessageBox.Show(this, ex.Message, "Workspace rejected", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var problem = WorkspaceGuard.ValidateRootLocation(full, WorkspaceAccess.ReadOnly);
        if (problem is not null)
        {
            MessageBox.Show(this, $"This folder can't be shared: {problem}", "Workspace rejected", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (_draft.Workspaces.Any(w => string.Equals(w.Path, full, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var baseName = WorkspaceGuard.SuggestName(full);
        var name = baseName;
        for (var i = 2; _draft.Workspaces.Any(w => w.Name.Equals(name, StringComparison.OrdinalIgnoreCase)); i++)
        {
            name = $"{baseName}-{i}";
        }

        _draft.Workspaces.Add(new WorkspaceRootOptions { Name = name, Path = full, Access = WorkspaceAccess.ReadOnly });
        RefreshWorkspaces();
    }

    private void RemoveWorkspace()
    {
        if (Selected is { } ws)
        {
            _draft.Workspaces.Remove(ws);
            RefreshWorkspaces();
        }
    }

    private void ToggleAccess()
    {
        if (Selected is not { } ws)
        {
            return;
        }

        if (ws.Access == WorkspaceAccess.ReadOnly)
        {
            var problem = WorkspaceGuard.ValidateRootLocation(ws.Path, WorkspaceAccess.ReadWrite);
            if (problem is not null)
            {
                MessageBox.Show(this, $"Can't make this workspace writable: {problem}", "Not allowed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var confirm = MessageBox.Show(this,
                $"Allow AI clients to create and modify files in:\n\n{ws.Path}\n\nWrites are atomic and logged, but keep backups of anything important.",
                "Grant write access?", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (confirm != DialogResult.Yes)
            {
                return;
            }

            ws.Access = WorkspaceAccess.ReadWrite;
        }
        else
        {
            ws.Access = WorkspaceAccess.ReadOnly;
        }

        RefreshWorkspaces();
    }

    private async Task SaveAsync()
    {
        _draft.EnableHttp = _enableHttp.Checked;
        _draft.AllowDelete = _allowDelete.Checked;
        _draft.HttpPort = (int)_port.Value;
        _draft.AllowedHosts = _allowedHosts.Text
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(h => h != "*")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        await _host.ApplySettingsAsync(SettingsStore.Clone(_draft));
    }

    private async Task RotateTokenAsync()
    {
        var confirm = MessageBox.Show(this, "Generate a new access token? Existing HTTP clients will stop working until reconfigured.",
            "Rotate token", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (confirm == DialogResult.Yes)
        {
            await _host.RotateTokenAsync();
        }
    }

    private void CopyClientConfig(bool http)
    {
        object config = http
            ? new
            {
                servers = new Dictionary<string, object>
                {
                    ["local-mcp"] = new
                    {
                        type = "http",
                        url = $"http://127.0.0.1:{_host.Options.HttpPort}/mcp",
                        headers = new Dictionary<string, string> { ["Authorization"] = $"Bearer {_host.AccessToken}" },
                    },
                },
            }
            : new
            {
                mcpServers = new Dictionary<string, object>
                {
                    ["local-mcp"] = new { command = Environment.ProcessPath ?? "LocalMcpServer.exe", args = new[] { "--stdio" } },
                },
            };

        Clipboard.SetText(JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
        _host.Audit.Write("ui", $"{(http ? "HTTP" : "stdio")} client configuration copied to clipboard.");
    }

    private void OpenLogs()
    {
        var directory = _host.Audit.LogDirectory;
        if (directory is not null && Directory.Exists(directory))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{directory}\"") { UseShellExecute = true });
        }
    }

    private void OnAuditEntry(AuditEntry entry)
    {
        if (!IsHandleCreated || IsDisposed)
        {
            return;
        }

        BeginInvoke(() =>
        {
            if (_log.TextLength > 400_000)
            {
                _log.Text = _log.Text[^200_000..];
            }

            _log.AppendText(entry + Environment.NewLine);
        });
    }

    private void OnStatusChanged()
    {
        if (IsDisposed)
        {
            return;
        }

        if (InvokeRequired)
        {
            BeginInvoke(OnStatusChanged);
            return;
        }

        _status.Text = _host.Status;
    }
}
