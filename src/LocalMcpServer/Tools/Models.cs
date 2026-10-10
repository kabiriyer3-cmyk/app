namespace LocalMcpServer.Tools;

// ---- Filesystem ----
public sealed record WorkspaceInfo(string Name, string Path, string Access, bool Exists);

public sealed record WorkspaceList(
    IReadOnlyList<WorkspaceInfo> Workspaces,
    IReadOnlyList<string> ConfigurationErrors,
    bool DeleteEnabled,
    long MaxReadBytes,
    long MaxWriteBytes,
    IReadOnlyList<string> BlockedWriteExtensions);

public sealed record DirectoryEntry(string Path, string Type, long? SizeBytes, DateTime ModifiedUtc, bool IsLink, bool Hidden);

public sealed record DirectoryListing(string Workspace, string Path, int Count, bool Truncated, IReadOnlyList<DirectoryEntry> Entries);

public sealed record TextFileContent(
    string Workspace, string Path, string Encoding, long SizeBytes, int StartLine, int LineCount, bool Truncated, string Content);

public sealed record BinaryFileContent(string Workspace, string Path, long SizeBytes, long Offset, int Length, string Base64, string HexPreview);

public sealed record FileDetails(
    string Workspace, string Path, bool Exists, string? Type, long? SizeBytes, DateTime? CreatedUtc, DateTime? ModifiedUtc,
    string? Attributes, bool IsLink, string? LinkTarget, string? Sha256);

public sealed record WriteResult(string Workspace, string Path, string Operation, long BytesWritten, bool Created, string? Sha256);

public sealed record OperationResult(string Workspace, string Operation, string Path, string? Detail = null);

public sealed record SearchMatch(string Path, int? Line, string? Text);

public sealed record SearchResult(string Workspace, string Root, int FilesScanned, bool Truncated, IReadOnlyList<SearchMatch> Matches);

// ---- System ----
public sealed record OsInfo(string ProductName, string? DisplayVersion, string Build, string Description, string Architecture);

public sealed record CpuInfo(string? Name, int LogicalProcessors, string Architecture);

public sealed record MemoryInfo(ulong TotalBytes, ulong AvailableBytes, uint LoadPercent);

public sealed record GpuInfo(string Name, string? DriverVersion, ulong? DedicatedMemoryBytes);

public sealed record DriveDetails(string Name, string Type, string? Format, long? TotalBytes, long? FreeBytes);

public sealed record ServerRuntimeInfo(string Version, string Framework, string ProcessArchitecture, int ProcessId, TimeSpan Uptime, bool Elevated);

public sealed record IdentityInfo(string MachineName, string UserName, string UserDomain);

public sealed record SystemInfo(
    OsInfo Os, CpuInfo Cpu, MemoryInfo Memory, IReadOnlyList<GpuInfo> Gpus, IReadOnlyList<DriveDetails> Drives,
    ServerRuntimeInfo Server, IdentityInfo? Identity);

public sealed record DevToolInfo(string Name, bool Found, string? Path);

public sealed record DevToolReport(IReadOnlyList<DevToolInfo> Tools, string? SteamPath, IReadOnlyList<string> SteamLibraries);

// ---- Modding ----
public sealed record ExtensionStat(string Extension, int Files, long Bytes);

public sealed record DetectedEcosystem(string Name, string Confidence, IReadOnlyList<string> Evidence);

public sealed record ModStructureReport(
    string Workspace, string Path, int Files, int Directories, long TotalBytes, bool Truncated,
    IReadOnlyList<DetectedEcosystem> Ecosystems, IReadOnlyList<ExtensionStat> Extensions,
    IReadOnlyList<DirectoryEntry> LargestFiles, IReadOnlyList<string> Warnings, IReadOnlyList<string> Tree);

public sealed record ConfigIssue(string Severity, string Message, long? Line, long? Column);

public sealed record ParsedConfig(string Workspace, string Path, string Format, bool Valid, IReadOnlyList<ConfigIssue> Issues, object? Summary, object? Data);

public sealed record FormatIdentification(
    string Workspace, string Path, long SizeBytes, string Format, string Category, string Confidence,
    IReadOnlyDictionary<string, object?> Details, string HexHead);

public sealed record DirectoryDiff(
    string Left, string Right, int LeftFiles, int RightFiles,
    IReadOnlyList<string> OnlyInLeft, IReadOnlyList<string> OnlyInRight, IReadOnlyList<string> Changed,
    int Identical, bool Truncated);

public sealed record FileHash(string Path, long SizeBytes, string Hash);

public sealed record HashReport(string Workspace, string Algorithm, int Count, bool Truncated, IReadOnlyList<FileHash> Files, string? ManifestWrittenTo);
