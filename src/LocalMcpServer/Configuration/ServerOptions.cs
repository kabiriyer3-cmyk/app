namespace LocalMcpServer.Configuration;

public enum WorkspaceAccess
{
    ReadOnly,
    ReadWrite,
}

public sealed class WorkspaceRootOptions
{
    /// <summary>Short identifier the AI client uses to address this workspace (e.g. "my-mod").</summary>
    public string Name { get; set; } = "";

    /// <summary>Absolute directory path. Environment variables such as %USERPROFILE% are expanded.</summary>
    public string Path { get; set; } = "";

    public WorkspaceAccess Access { get; set; } = WorkspaceAccess.ReadOnly;
}

public sealed class ServerOptions
{
    public List<WorkspaceRootOptions> Workspaces { get; set; } = [];

    /// <summary>Expose Streamable HTTP on 127.0.0.1 while the tray app runs. Stdio mode is always available via --stdio.</summary>
    public bool EnableHttp { get; set; } = true;

    public int HttpPort { get; set; } = 39217;

    /// <summary>delete_path is disabled unless explicitly enabled. Deletions go to the Recycle Bin.</summary>
    public bool AllowDelete { get; set; }

    /// <summary>Refuse to start when launched from an elevated (administrator) process.</summary>
    public bool RefuseElevated { get; set; } = true;

    /// <summary>Include machine name / user name in get_system_info. Off by default for privacy.</summary>
    public bool IncludeMachineIdentifiers { get; set; }

    public long MaxReadBytes { get; set; } = 16L * 1024 * 1024;

    public long MaxWriteBytes { get; set; } = 16L * 1024 * 1024;

    public long MaxCopyBytes { get; set; } = 4L * 1024 * 1024 * 1024;

    public int MaxListEntries { get; set; } = 5000;

    public int MaxSearchResults { get; set; } = 500;

    public List<string> BlockedWriteExtensions { get; set; } =
    [
        ".exe", ".dll", ".sys", ".drv", ".com", ".scr", ".msi", ".msix", ".appx",
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".jse", ".wsf", ".wsh",
        ".hta", ".lnk", ".url", ".reg", ".cpl", ".inf",
    ];
}
