using System.ComponentModel;
using System.IO.Enumeration;
using System.Text;
using LocalMcpServer.Configuration;
using LocalMcpServer.Infrastructure;
using LocalMcpServer.Modding;
using LocalMcpServer.Security;
using Microsoft.VisualBasic.FileIO;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace LocalMcpServer.Tools;

/// <summary>Workspace-scoped file system tools. Every path is resolved through <see cref="WorkspaceGuard"/>.</summary>
[McpServerToolType]
public sealed class FileSystemTools(WorkspaceGuard guard, ServerOptions options, AuditLog audit)
{
    private const string WorkspaceDescription = "Workspace name returned by list_workspaces.";
    private const string PathDescription = "Path relative to the workspace root, using / or \\. Empty string means the root.";

    [McpServerTool(Name = "list_workspaces", Title = "List workspaces", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Lists the directories this server is allowed to access, their access level (ReadOnly/ReadWrite) and the active limits. Call this first.")]
    public WorkspaceList ListWorkspaces() => ToolExecution.Run(audit, "list_workspaces", () =>
        new WorkspaceList(
            guard.Roots.Select(r => new WorkspaceInfo(r.Name, r.FullPath, r.Access.ToString(), Directory.Exists(r.FullPath))).ToList(),
            guard.ConfigurationErrors,
            options.AllowDelete,
            options.MaxReadBytes,
            options.MaxWriteBytes,
            options.BlockedWriteExtensions));

    [McpServerTool(Name = "list_directory", Title = "List directory", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Lists files and folders in a workspace directory. Symbolic links and junctions are reported but never followed.")]
    public DirectoryListing ListDirectory(
        [Description(WorkspaceDescription)] string workspace,
        [Description(PathDescription)] string path = "",
        [Description("Recurse into subdirectories.")] bool recursive = false,
        [Description("Wildcard filter applied to names, e.g. *.pak or *.ini.")] string pattern = "*",
        [Description("Maximum number of entries to return.")] int maxEntries = 1000,
        CancellationToken cancellationToken = default) => ToolExecution.Run(audit, "list_directory", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        if (!Directory.Exists(target.FullPath))
        {
            throw new McpException($"Directory not found: {target.Display}");
        }

        var limit = Math.Clamp(maxEntries, 1, options.MaxListEntries);
        var entries = new List<DirectoryEntry>();
        var truncated = false;

        foreach (var item in WorkspaceWalker.Walk(target.Root, target.FullPath, recursive, cancellationToken: cancellationToken))
        {
            if (!MatchesPattern(pattern, item.Info.Name))
            {
                continue;
            }

            if (entries.Count >= limit)
            {
                truncated = true;
                break;
            }

            entries.Add(ToEntry(item));
        }

        audit.Write("list_directory", $"{target.Display} ({entries.Count} entries{(recursive ? ", recursive" : "")})");
        return new DirectoryListing(target.Root.Name, target.RelativePath, entries.Count, truncated, entries);
    });

    [McpServerTool(Name = "read_text_file", Title = "Read text file", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Reads a text file (UTF-8/UTF-16 detected from BOM) with optional line range. Binary files are refused; use read_binary_file or identify_file_format instead.")]
    public TextFileContent ReadTextFile(
        [Description(WorkspaceDescription)] string workspace,
        [Description(PathDescription)] string path,
        [Description("1-based line to start from.")] int startLine = 1,
        [Description("Maximum number of lines to return.")] int maxLines = 2000) => ToolExecution.Run(audit, "read_text_file", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        var info = new FileInfo(target.FullPath);
        if (!info.Exists)
        {
            throw new McpException($"File not found: {target.Display}");
        }

        startLine = Math.Max(1, startLine);
        maxLines = Math.Clamp(maxLines, 1, 50_000);

        using var stream = new FileStream(target.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024);
        var head = new byte[8192];
        var headLength = stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        if (FormatSniffer.LooksBinary(head.AsSpan(0, headLength)))
        {
            throw new McpException($"{target.Display} looks like a binary file. Use identify_file_format or read_binary_file.");
        }

        stream.Position = 0;
        using var reader = new StreamReader(stream, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true);
        var builder = new StringBuilder();
        var lineNumber = 0;
        var returned = 0;
        long characters = 0;
        var truncated = false;

        while (reader.ReadLine() is { } line)
        {
            lineNumber++;
            if (lineNumber < startLine)
            {
                continue;
            }

            if (returned >= maxLines || characters + line.Length > options.MaxReadBytes)
            {
                truncated = true;
                break;
            }

            builder.Append(line).Append('\n');
            returned++;
            characters += line.Length + 1;
        }

        audit.Write("read_text_file", $"{target.Display} lines {startLine}-{startLine + Math.Max(returned, 1) - 1}");
        return new TextFileContent(target.Root.Name, target.RelativePath, reader.CurrentEncoding.WebName, info.Length,
            startLine, returned, truncated, builder.ToString());
    });

    [McpServerTool(Name = "read_binary_file", Title = "Read binary range", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Reads a byte range of any file and returns it as base64 plus a hex preview. Max 1 MiB per call.")]
    public BinaryFileContent ReadBinaryFile(
        [Description(WorkspaceDescription)] string workspace,
        [Description(PathDescription)] string path,
        [Description("Byte offset to start reading at. Negative values count from the end of the file.")] long offset = 0,
        [Description("Number of bytes to read (max 1048576).")] int length = 65536) => ToolExecution.Run(audit, "read_binary_file", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        var info = new FileInfo(target.FullPath);
        if (!info.Exists)
        {
            throw new McpException($"File not found: {target.Display}");
        }

        length = (int)Math.Clamp(length, 1, Math.Min(1024 * 1024, options.MaxReadBytes));
        var start = offset < 0 ? Math.Max(0, info.Length + offset) : Math.Min(offset, info.Length);

        using var stream = new FileStream(target.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        stream.Position = start;
        var buffer = new byte[(int)Math.Min(length, info.Length - start)];
        var read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);

        audit.Write("read_binary_file", $"{target.Display} [{start}..{start + read})");
        return new BinaryFileContent(target.Root.Name, target.RelativePath, info.Length, start, read,
            Convert.ToBase64String(buffer, 0, read), Fmt.Hex(buffer.AsSpan(0, read), 64));
    });

    [McpServerTool(Name = "get_file_info", Title = "Get file info", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Returns metadata for a file or directory: size, timestamps, attributes, link status and optionally a SHA-256 hash.")]
    public FileDetails GetFileInfo(
        [Description(WorkspaceDescription)] string workspace,
        [Description(PathDescription)] string path,
        [Description("Compute the SHA-256 of the file (files only). Use this value as expectedSha256 when writing.")] bool computeHash = false) =>
        ToolExecution.Run(audit, "get_file_info", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        FileSystemInfo? info = Directory.Exists(target.FullPath) ? new DirectoryInfo(target.FullPath)
            : File.Exists(target.FullPath) ? new FileInfo(target.FullPath)
            : null;

        if (info is null)
        {
            return new FileDetails(target.Root.Name, target.RelativePath, false, null, null, null, null, null, false, null, null);
        }

        var isLink = info.LinkTarget is not null;
        string? hash = null;
        if (computeHash && info is FileInfo file)
        {
            if (file.Length > options.MaxCopyBytes)
            {
                throw new McpException("File is too large to hash under the current limits.");
            }

            hash = Hashing.ComputeFile(file.FullName);
        }

        return new FileDetails(target.Root.Name, target.RelativePath, true, info is DirectoryInfo ? "directory" : "file",
            (info as FileInfo)?.Length, info.CreationTimeUtc, info.LastWriteTimeUtc, info.Attributes.ToString(),
            isLink, isLink ? info.LinkTarget : null, hash);
    });

    [McpServerTool(Name = "search_files", Title = "Search files", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Finds files by name wildcard and optionally by text content (plain substring, line-by-line). Binary and very large files are skipped for content search.")]
    public SearchResult SearchFiles(
        [Description(WorkspaceDescription)] string workspace,
        [Description("Directory to search, relative to the workspace root.")] string path = "",
        [Description("File name wildcard, e.g. *.ini or DefaultGame*.")] string namePattern = "*",
        [Description("Optional text to look for inside files.")] string? contentQuery = null,
        [Description("Case-sensitive content match.")] bool caseSensitive = false,
        [Description("Maximum matches to return.")] int maxResults = 200,
        CancellationToken cancellationToken = default) => ToolExecution.Run(audit, "search_files", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        if (!Directory.Exists(target.FullPath))
        {
            throw new McpException($"Directory not found: {target.Display}");
        }

        var limit = Math.Clamp(maxResults, 1, options.MaxSearchResults);
        var comparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        var matches = new List<SearchMatch>();
        var scanned = 0;
        var truncated = false;

        foreach (var item in WorkspaceWalker.Walk(target.Root, target.FullPath, recursive: true, cancellationToken: cancellationToken))
        {
            if (item.Info is not FileInfo file || !MatchesPattern(namePattern, file.Name))
            {
                continue;
            }

            if (string.IsNullOrEmpty(contentQuery))
            {
                matches.Add(new SearchMatch(item.RelativePath, null, null));
            }
            else if (file.Length <= Math.Min(options.MaxReadBytes, 32L * 1024 * 1024))
            {
                scanned++;
                foreach (var hit in ScanFile(file, item.RelativePath, contentQuery, comparison, limit - matches.Count))
                {
                    matches.Add(hit);
                }
            }

            if (matches.Count >= limit)
            {
                truncated = true;
                break;
            }
        }

        audit.Write("search_files", $"{target.Display} name='{namePattern}' content='{contentQuery}' -> {matches.Count}");
        return new SearchResult(target.Root.Name, target.RelativePath, scanned, truncated, matches);
    });

    [McpServerTool(Name = "write_text_file", Title = "Write text file", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false)]
    [Description("Writes a text file inside a ReadWrite workspace. Writes are atomic (temp file + rename). Pass expectedSha256 (from get_file_info) to refuse the write if the file changed since you read it.")]
    public WriteResult WriteTextFile(
        [Description(WorkspaceDescription)] string workspace,
        [Description(PathDescription)] string path,
        [Description("Full text content to write.")] string content,
        [Description("overwrite (default), create (fail if exists) or append.")] string mode = "overwrite",
        [Description("utf-8 (default), utf-8-bom or utf-16le. Unreal config files are usually utf-8 or utf-16le.")] string encoding = "utf-8",
        [Description("Create missing parent directories.")] bool createDirectories = true,
        [Description("Optional optimistic-concurrency check: SHA-256 the file must currently have.")] string? expectedSha256 = null) =>
        ToolExecution.Run(audit, "write_text_file", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Write);
        var textEncoding = ResolveEncoding(encoding);
        long bytes = textEncoding.GetByteCount(content) + textEncoding.GetPreamble().Length;
        if (bytes > options.MaxWriteBytes)
        {
            throw new McpException($"Content is {bytes:N0} bytes, above the {options.MaxWriteBytes:N0} byte write limit.");
        }

        if (Directory.Exists(target.FullPath))
        {
            throw new McpException($"{target.Display} is a directory.");
        }

        var directory = Path.GetDirectoryName(target.FullPath)!;
        if (!Directory.Exists(directory))
        {
            if (!createDirectories)
            {
                throw new McpException("Parent directory does not exist (set createDirectories=true).");
            }

            Directory.CreateDirectory(directory);
        }

        var existed = File.Exists(target.FullPath);
        if (!string.IsNullOrWhiteSpace(expectedSha256))
        {
            if (!existed)
            {
                throw new McpException("expectedSha256 was given but the file does not exist.");
            }

            var actual = Hashing.ComputeFile(target.FullPath);
            if (!actual.Equals(expectedSha256.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                throw new McpException($"File changed since it was read (expected {expectedSha256}, found {actual}). Re-read it before writing.");
            }
        }

        var normalizedMode = mode.Trim().ToLowerInvariant();
        switch (normalizedMode)
        {
            case "overwrite":
                WriteAtomic(target.FullPath, content, textEncoding, overwrite: true);
                break;
            case "create":
                if (existed)
                {
                    throw new McpException($"{target.Display} already exists (mode=create).");
                }

                WriteAtomic(target.FullPath, content, textEncoding, overwrite: false);
                break;
            case "append":
                if (existed && new FileInfo(target.FullPath).Length + bytes > options.MaxReadBytes)
                {
                    throw new McpException("Appending would grow the file beyond the configured read limit.");
                }

                File.AppendAllText(target.FullPath, content, textEncoding);
                break;
            default:
                throw new McpException("mode must be 'overwrite', 'create' or 'append'.");
        }

        var hash = Hashing.ComputeFile(target.FullPath);
        audit.Write("write_text_file", $"{target.Display} ({normalizedMode}, {bytes:N0} bytes)");
        return new WriteResult(target.Root.Name, target.RelativePath, normalizedMode, bytes, !existed, hash);
    });

    [McpServerTool(Name = "create_directory", Title = "Create directory", ReadOnly = false, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Creates a directory (and missing parents) inside a ReadWrite workspace.")]
    public OperationResult CreateDirectory(
        [Description(WorkspaceDescription)] string workspace,
        [Description(PathDescription)] string path) => ToolExecution.Run(audit, "create_directory", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Write);
        if (File.Exists(target.FullPath))
        {
            throw new McpException($"A file already exists at {target.Display}.");
        }

        Directory.CreateDirectory(target.FullPath);
        audit.Write("create_directory", target.Display);
        return new OperationResult(target.Root.Name, "create_directory", target.RelativePath);
    });

    [McpServerTool(Name = "copy_file", Title = "Copy file", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false)]
    [Description("Copies a file. The source may be in any workspace (including ReadOnly, e.g. game files); the destination must be in a ReadWrite workspace. Handy for backups before editing.")]
    public OperationResult CopyFile(
        [Description("Workspace containing the source file.")] string sourceWorkspace,
        [Description("Source path relative to its workspace.")] string sourcePath,
        [Description("Destination workspace (must be ReadWrite).")] string destinationWorkspace,
        [Description("Destination path relative to its workspace.")] string destinationPath,
        [Description("Replace the destination if it exists.")] bool overwrite = false) => ToolExecution.Run(audit, "copy_file", () =>
    {
        var source = guard.Resolve(sourceWorkspace, sourcePath, AccessKind.Read);
        var destination = guard.Resolve(destinationWorkspace, destinationPath, AccessKind.Write);
        var info = new FileInfo(source.FullPath);
        if (!info.Exists)
        {
            throw new McpException($"File not found: {source.Display}");
        }

        if (info.Length > options.MaxCopyBytes)
        {
            throw new McpException($"File is {Fmt.Size(info.Length)}, above the copy limit of {Fmt.Size(options.MaxCopyBytes)}.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(destination.FullPath)!);
        File.Copy(source.FullPath, destination.FullPath, overwrite);
        audit.Write("copy_file", $"{source.Display} -> {destination.Display}");
        return new OperationResult(destination.Root.Name, "copy_file", destination.RelativePath, $"from {source.Display}");
    });

    [McpServerTool(Name = "move_path", Title = "Move or rename", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false)]
    [Description("Moves or renames a file or directory within one ReadWrite workspace.")]
    public OperationResult MovePath(
        [Description(WorkspaceDescription)] string workspace,
        [Description("Existing path.")] string sourcePath,
        [Description("New path.")] string destinationPath,
        [Description("Replace an existing destination file (files only).")] bool overwrite = false) => ToolExecution.Run(audit, "move_path", () =>
    {
        var source = guard.Resolve(workspace, sourcePath, AccessKind.Write);
        var destination = guard.Resolve(workspace, destinationPath, AccessKind.Write);
        Directory.CreateDirectory(Path.GetDirectoryName(destination.FullPath)!);

        if (File.Exists(source.FullPath))
        {
            File.Move(source.FullPath, destination.FullPath, overwrite);
        }
        else if (Directory.Exists(source.FullPath))
        {
            if (WorkspaceGuard.IsSameOrUnder(destination.FullPath, source.FullPath))
            {
                throw new McpException("Cannot move a directory into itself.");
            }

            Directory.Move(source.FullPath, destination.FullPath);
        }
        else
        {
            throw new McpException($"Not found: {source.Display}");
        }

        audit.Write("move_path", $"{source.Display} -> {destination.Display}");
        return new OperationResult(workspace, "move_path", destination.RelativePath, $"from {source.RelativePath}");
    });

    [McpServerTool(Name = "delete_path", Title = "Delete (to Recycle Bin)", ReadOnly = false, Destructive = true, Idempotent = false, OpenWorld = false)]
    [Description("Sends a file or directory to the Windows Recycle Bin. Disabled unless the user enabled 'Allow delete'. Directories containing links are refused.")]
    public OperationResult DeletePath(
        [Description(WorkspaceDescription)] string workspace,
        [Description(PathDescription)] string path,
        [Description("Required to delete a non-empty directory.")] bool recursive = false) => ToolExecution.Run(audit, "delete_path", () =>
    {
        if (!options.AllowDelete)
        {
            throw new McpException("Access denied: deletion is disabled in the server settings.");
        }

        var target = guard.Resolve(workspace, path, AccessKind.Write);
        if (File.Exists(target.FullPath))
        {
            FileSystem.DeleteFile(target.FullPath, UIOption.OnlyErrorDialogs, RecycleOption.SendToRecycleBin);
        }
        else if (Directory.Exists(target.FullPath))
        {
            var children = WorkspaceWalker.Walk(target.Root, target.FullPath, recursive: true).ToList();
            if (children.Count > 0 && !recursive)
            {
                throw new McpException("Directory is not empty; pass recursive=true to delete it.");
            }

            if (children.Any(c => c.IsLink) || new DirectoryInfo(target.FullPath).LinkTarget is not null)
            {
                throw new McpException("Access denied: directory contains symbolic links or junctions; remove them manually.");
            }

            FileSystem.DeleteDirectory(target.FullPath, UIOption.OnlyErrorDialogs, RecycleOption.SendToRecycleBin);
        }
        else
        {
            throw new McpException($"Not found: {target.Display}");
        }

        audit.Write("delete_path", $"{target.Display} -> Recycle Bin");
        return new OperationResult(target.Root.Name, "delete_path", target.RelativePath, "moved to Recycle Bin");
    });

    // ---------------------------------------------------------------------------------------------------------------

    internal static bool MatchesPattern(string? pattern, string name) =>
        string.IsNullOrWhiteSpace(pattern) || pattern == "*" || FileSystemName.MatchesSimpleExpression(pattern, name, ignoreCase: true);

    private static DirectoryEntry ToEntry(WalkEntry item) => new(
        item.RelativePath,
        item.Info is DirectoryInfo ? "directory" : "file",
        (item.Info as FileInfo)?.Length,
        item.Info.LastWriteTimeUtc,
        item.IsLink,
        item.Info.Attributes.HasFlag(FileAttributes.Hidden));

    private static IEnumerable<SearchMatch> ScanFile(FileInfo file, string relativePath, string query, StringComparison comparison, int remaining)
    {
        var results = new List<SearchMatch>();
        try
        {
            using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var head = new byte[4096];
            var read = stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
            if (FormatSniffer.LooksBinary(head.AsSpan(0, read)))
            {
                return results;
            }

            stream.Position = 0;
            using var reader = new StreamReader(stream, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true);
            var lineNumber = 0;
            while (reader.ReadLine() is { } line && results.Count < remaining)
            {
                lineNumber++;
                if (line.Contains(query, comparison))
                {
                    var text = line.Trim();
                    results.Add(new SearchMatch(relativePath, lineNumber, text.Length > 240 ? text[..240] + "…" : text));
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Locked or inaccessible files are skipped.
        }

        return results;
    }

    private static Encoding ResolveEncoding(string name) => name.Trim().ToLowerInvariant() switch
    {
        "utf-8" or "utf8" => new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        "utf-8-bom" or "utf8bom" => new UTF8Encoding(encoderShouldEmitUTF8Identifier: true),
        "utf-16le" or "utf-16" or "unicode" => new UnicodeEncoding(bigEndian: false, byteOrderMark: true),
        _ => throw new McpException("encoding must be utf-8, utf-8-bom or utf-16le."),
    };

    private static void WriteAtomic(string fullPath, string content, Encoding encoding, bool overwrite)
    {
        var directory = Path.GetDirectoryName(fullPath)!;
        var temp = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.mcp-tmp");
        try
        {
            File.WriteAllText(temp, content, encoding);
            File.Move(temp, fullPath, overwrite);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }
}
