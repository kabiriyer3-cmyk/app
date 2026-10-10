using LocalMcpServer.Configuration;
using ModelContextProtocol;

namespace LocalMcpServer.Security;

public enum AccessKind
{
    Read,
    Write,
}

public sealed record WorkspaceRoot(string Name, string FullPath, WorkspaceAccess Access);

public sealed record ResolvedPath(WorkspaceRoot Root, string FullPath, string RelativePath)
{
    public bool IsRoot => RelativePath.Length == 0;

    public string Display => $"{Root.Name}:/{RelativePath}";
}

/// <summary>
/// The single permission boundary for every filesystem tool.
/// Every path an AI client sends goes through <see cref="Resolve"/>; nothing touches disk without it.
/// </summary>
public sealed class WorkspaceGuard
{
    private const StringComparison PathComparison = StringComparison.OrdinalIgnoreCase;

    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
    };

    private static readonly char[] InvalidSegmentChars = Path.GetInvalidFileNameChars();

    private readonly Dictionary<string, WorkspaceRoot> _roots = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _blockedWriteExtensions;
    private readonly List<string> _configurationErrors = [];

    public WorkspaceGuard(ServerOptions options)
    {
        _blockedWriteExtensions = new HashSet<string>(
            options.BlockedWriteExtensions.Select(e => e.StartsWith('.') ? e : "." + e),
            StringComparer.OrdinalIgnoreCase);

        foreach (var ws in options.Workspaces)
        {
            if (string.IsNullOrWhiteSpace(ws.Name) || string.IsNullOrWhiteSpace(ws.Path))
            {
                _configurationErrors.Add("Workspace entries need both a name and a path.");
                continue;
            }

            if (!IsValidWorkspaceName(ws.Name))
            {
                _configurationErrors.Add($"Workspace name '{ws.Name}' is invalid (use letters, digits, '-', '_' or '.').");
                continue;
            }

            string full;
            try
            {
                full = NormalizeDirectory(ws.Path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                _configurationErrors.Add($"Workspace '{ws.Name}' rejected: {ex.Message}");
                continue;
            }

            var problem = ValidateRootLocation(full, ws.Access);
            if (problem is not null)
            {
                _configurationErrors.Add($"Workspace '{ws.Name}' rejected: {problem}");
                continue;
            }

            if (!_roots.TryAdd(ws.Name, new WorkspaceRoot(ws.Name, full, ws.Access)))
            {
                _configurationErrors.Add($"Duplicate workspace name '{ws.Name}'.");
            }
        }
    }

    public IReadOnlyCollection<WorkspaceRoot> Roots => _roots.Values;

    public IReadOnlyList<string> ConfigurationErrors => _configurationErrors;

    public ResolvedPath Resolve(string? workspace, string? relativePath, AccessKind access)
    {
        if (string.IsNullOrWhiteSpace(workspace) || !_roots.TryGetValue(workspace.Trim(), out var root))
        {
            throw Deny($"Unknown workspace '{workspace}'. Call list_workspaces to see the configured workspaces.");
        }

        if (access == AccessKind.Write && root.Access != WorkspaceAccess.ReadWrite)
        {
            throw Deny($"Workspace '{root.Name}' is read-only.");
        }

        var relative = NormalizeRelative(relativePath);
        var full = relative.Length == 0
            ? root.FullPath
            : Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine(root.FullPath, relative)));

        if (!IsSameOrUnder(full, root.FullPath))
        {
            throw Deny("Path escapes the workspace boundary.");
        }

        EnsureNoEscapingLinks(root, full);

        var display = ToRelative(root, full);
        if (access == AccessKind.Write)
        {
            if (display.Length == 0)
            {
                throw Deny("The workspace root itself cannot be modified.");
            }

            var extension = Path.GetExtension(full);
            if (extension.Length > 0 && _blockedWriteExtensions.Contains(extension))
            {
                throw Deny($"Writing '{extension}' files is blocked by policy.");
            }
        }

        return new ResolvedPath(root, full, display);
    }

    public WorkspaceRoot GetRoot(string workspace) =>
        _roots.TryGetValue(workspace, out var root)
            ? root
            : throw Deny($"Unknown workspace '{workspace}'.");

    public static string ToRelative(WorkspaceRoot root, string fullPath)
    {
        var relative = Path.GetRelativePath(root.FullPath, fullPath);
        return relative == "." ? "" : relative.Replace('\\', '/');
    }

    public static string NormalizeDirectory(string path)
    {
        var expanded = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
        if (expanded.StartsWith(@"\\", StringComparison.Ordinal) || expanded.StartsWith("//", StringComparison.Ordinal))
        {
            throw new ArgumentException("UNC, device (\\\\?\\, \\\\.\\) and network paths are not allowed as workspaces.");
        }

        if (!Path.IsPathFullyQualified(expanded))
        {
            throw new ArgumentException("Workspace paths must be absolute (e.g. D:\\Modding\\MyMod).");
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(expanded));
    }

    /// <summary>Returns a human-readable reason when a directory must not become a workspace root, otherwise null.</summary>
    public static string? ValidateRootLocation(string fullPath, WorkspaceAccess access)
    {
        if (!Directory.Exists(fullPath))
        {
            return "directory does not exist.";
        }

        if (string.Equals(Path.GetPathRoot(fullPath)?.TrimEnd('\\'), fullPath.TrimEnd('\\'), PathComparison))
        {
            return "whole drives are too broad; pick a specific folder.";
        }

        var attributes = File.GetAttributes(fullPath);
        if (attributes.HasFlag(FileAttributes.ReparsePoint) && new DirectoryInfo(fullPath).LinkTarget is not null)
        {
            return "the workspace root must be a real directory, not a symbolic link or junction.";
        }

        var protectedTrees = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        }.Where(p => !string.IsNullOrEmpty(p)).Select(Path.TrimEndingDirectorySeparator);

        foreach (var tree in protectedTrees)
        {
            if (IsSameOrUnder(fullPath, tree) && access == WorkspaceAccess.ReadWrite)
            {
                return $"'{tree}' is a protected system location and can only be shared read-only.";
            }

            if (IsSameOrUnder(tree, fullPath))
            {
                return $"the folder contains the protected system location '{tree}'.";
            }
        }

        // Never let a workspace contain the server's own configuration or token: that would let a client grant itself access.
        foreach (var own in new[] { SettingsStore.AppDataDirectory, SettingsStore.LocalDataDirectory })
        {
            var ownFull = Path.TrimEndingDirectorySeparator(Path.GetFullPath(own));
            if (IsSameOrUnder(ownFull, fullPath) || IsSameOrUnder(fullPath, ownFull))
            {
                return "the folder overlaps the server's own settings/token directory.";
            }
        }

        var exeDir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        if (access == WorkspaceAccess.ReadWrite && (IsSameOrUnder(exeDir, fullPath) || IsSameOrUnder(fullPath, exeDir)))
        {
            return "the server's own install folder cannot be writable.";
        }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(profile) && string.Equals(fullPath, Path.TrimEndingDirectorySeparator(profile), PathComparison))
        {
            return "the whole user profile is too broad; pick a specific folder.";
        }

        return null;
    }

    public static bool IsValidWorkspaceName(string name) =>
        name.Length is > 0 and <= 64 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    public static string SuggestName(string fullPath)
    {
        var leaf = Path.GetFileName(fullPath.TrimEnd('\\'));
        var cleaned = new string(leaf.Select(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '-').ToArray()).Trim('-');
        return string.IsNullOrEmpty(cleaned) ? "workspace" : cleaned.Length > 64 ? cleaned[..64] : cleaned;
    }

    internal static bool IsSameOrUnder(string path, string parent)
    {
        var p = Path.TrimEndingDirectorySeparator(path);
        var root = Path.TrimEndingDirectorySeparator(parent);
        if (string.Equals(p, root, PathComparison))
        {
            return true;
        }

        var prefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        return p.StartsWith(prefix, PathComparison);
    }

    private static string NormalizeRelative(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return "";
        }

        var path = input.Trim().Replace('/', '\\');

        if (path.Contains('\0'))
        {
            throw Deny("Null characters are not allowed in paths.");
        }

        if (path.StartsWith('\\') || Path.IsPathRooted(path))
        {
            throw Deny("Paths must be relative to the workspace root (no drive letters or leading slashes).");
        }

        if (path.Contains(':'))
        {
            throw Deny("':' is not allowed (drive letters and NTFS alternate data streams are blocked).");
        }

        var segments = new List<string>();
        foreach (var segment in path.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == ".")
            {
                continue;
            }

            if (segment == "..")
            {
                throw Deny("'..' segments are not allowed.");
            }

            if (segment.IndexOfAny(InvalidSegmentChars) >= 0)
            {
                throw Deny($"Path segment '{segment}' contains invalid characters.");
            }

            if (segment.EndsWith('.') || segment.EndsWith(' '))
            {
                throw Deny($"Path segment '{segment}' ends with '.' or a space, which Windows silently strips.");
            }

            var stem = segment.Split('.')[0].TrimEnd();
            if (ReservedDeviceNames.Contains(stem))
            {
                throw Deny($"'{segment}' is a reserved Windows device name.");
            }

            segments.Add(segment);
        }

        return string.Join('\\', segments);
    }

    private static void EnsureNoEscapingLinks(WorkspaceRoot root, string full)
    {
        var relative = Path.GetRelativePath(root.FullPath, full);
        if (relative == ".")
        {
            return;
        }

        var current = root.FullPath;
        foreach (var segment in relative.Split(Path.DirectorySeparatorChar))
        {
            current = Path.Combine(current, segment);

            FileSystemInfo? info = Directory.Exists(current) ? new DirectoryInfo(current)
                : File.Exists(current) ? new FileInfo(current)
                : null;

            if (info is null)
            {
                return; // The remainder does not exist yet (e.g. a file about to be created).
            }

            if (!info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                continue;
            }

            // Symlinks and junctions report a LinkTarget; other reparse points (OneDrive placeholders, dedup) do not.
            if (info.LinkTarget is null)
            {
                continue;
            }

            FileSystemInfo? target;
            try
            {
                target = info.ResolveLinkTarget(returnFinalTarget: true);
            }
            catch (IOException)
            {
                target = null;
            }

            if (target is null)
            {
                throw Deny($"'{segment}' is a link whose target cannot be verified.");
            }

            var targetFull = Path.TrimEndingDirectorySeparator(Path.GetFullPath(target.FullName));
            if (!IsSameOrUnder(targetFull, root.FullPath))
            {
                throw Deny($"'{segment}' is a symbolic link or junction pointing outside the workspace.");
            }
        }
    }

    private static McpException Deny(string reason) => new($"Access denied: {reason}");
}
