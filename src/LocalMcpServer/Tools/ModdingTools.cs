using System.ComponentModel;
using System.Text;
using System.Text.Json.Nodes;
using LocalMcpServer.Configuration;
using LocalMcpServer.Infrastructure;
using LocalMcpServer.Modding;
using LocalMcpServer.Security;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace LocalMcpServer.Tools;

/// <summary>Helpers for inspecting mod folders and parsing the formats game mods are made of.</summary>
[McpServerToolType]
public sealed class ModdingTools(WorkspaceGuard guard, ServerOptions options, AuditLog audit)
{
    private const string WorkspaceDescription = "Workspace name returned by list_workspaces.";

    [McpServerTool(Name = "inspect_mod_structure", Title = "Inspect mod structure", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Walks a mod or game folder and reports a tree, size/extension statistics, the detected modding ecosystem (Unreal PAK/IoStore, Unity/BepInEx, Minecraft resource & shader packs, Bethesda, Source) and common packaging mistakes.")]
    public ModStructureReport InspectModStructure(
        [Description(WorkspaceDescription)] string workspace,
        [Description("Folder to inspect, relative to the workspace root.")] string path = "",
        [Description("Maximum depth to walk.")] int maxDepth = 8,
        [Description("Maximum number of lines in the rendered tree.")] int maxTreeLines = 300,
        CancellationToken cancellationToken = default) => ToolExecution.Run(audit, "inspect_mod_structure", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        if (!Directory.Exists(target.FullPath))
        {
            throw new McpException($"Directory not found: {target.Display}");
        }

        maxDepth = Math.Clamp(maxDepth, 1, 32);
        const int maxFiles = 200_000;

        var files = new List<(FileInfo Info, string Relative)>();
        var directories = 0;
        var truncated = false;
        var directoryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in WorkspaceWalker.Walk(target.Root, target.FullPath, recursive: true, maxDepth, cancellationToken))
        {
            if (item.Info is DirectoryInfo)
            {
                directories++;
                directoryNames.Add(item.Info.Name);
                continue;
            }

            if (files.Count >= maxFiles)
            {
                truncated = true;
                break;
            }

            files.Add(((FileInfo)item.Info, item.RelativePath));
        }

        var extensions = files
            .GroupBy(f => f.Info.Extension.Length > 0 ? f.Info.Extension.ToLowerInvariant() : "(none)")
            .Select(g => new ExtensionStat(g.Key, g.Count(), g.Sum(f => f.Info.Length)))
            .OrderByDescending(s => s.Bytes)
            .ToList();

        var largest = files.OrderByDescending(f => f.Info.Length).Take(10)
            .Select(f => new DirectoryEntry(f.Relative, "file", f.Info.Length, f.Info.LastWriteTimeUtc, false, false))
            .ToList();

        var warnings = new List<string>();
        var ecosystems = DetectEcosystems(files, directoryNames, warnings);

        foreach (var (info, relative) in files)
        {
            if (info.FullName.Length > 240)
            {
                warnings.Add($"Long path ({info.FullName.Length} chars) may break older games/tools: {relative}");
            }

            if (relative.Any(c => c > 127))
            {
                warnings.Add($"Non-ASCII path may not load in some engines/packers: {relative}");
            }
        }

        var tree = new List<string> { (target.RelativePath.Length == 0 ? target.Root.Name : target.RelativePath) + "/" };
        BuildTree(new DirectoryInfo(target.FullPath), "  ", 1, maxDepth, tree, Math.Clamp(maxTreeLines, 10, 2000));

        audit.Write("inspect_mod_structure", $"{target.Display} ({files.Count} files)");
        return new ModStructureReport(target.Root.Name, target.RelativePath, files.Count, directories, files.Sum(f => f.Info.Length),
            truncated, ecosystems, extensions, largest, warnings.Distinct().Take(100).ToList(), tree);
    });

    [McpServerTool(Name = "parse_config_file", Title = "Parse config file", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Parses and validates INI (incl. Unreal +/-/./! array operators), JSON (comments allowed: .json/.mcmeta/.uplugin/.uproject), XML (DTDs disabled) or .properties (OptiFine/Iris shaders.properties) files and returns structured data plus line-numbered issues.")]
    public ParsedConfig ParseConfigFile(
        [Description(WorkspaceDescription)] string workspace,
        [Description("File path relative to the workspace root.")] string path,
        [Description("auto (by extension), ini, json, xml or properties.")] string format = "auto",
        [Description("Return the parsed data, not just the summary and issues.")] bool includeData = true) =>
        ToolExecution.Run(audit, "parse_config_file", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        var info = new FileInfo(target.FullPath);
        if (!info.Exists)
        {
            throw new McpException($"File not found: {target.Display}");
        }

        if (info.Length > options.MaxReadBytes)
        {
            throw new McpException($"File exceeds the {Fmt.Size(options.MaxReadBytes)} read limit.");
        }

        var resolvedFormat = format.Trim().ToLowerInvariant() switch
        {
            "auto" => info.Extension.ToLowerInvariant() switch
            {
                ".ini" or ".cfg" => "ini",
                ".json" or ".mcmeta" or ".uplugin" or ".uproject" or ".json5" => "json",
                ".xml" or ".config" or ".csproj" or ".props" or ".targets" => "xml",
                ".properties" or ".lang" => "properties",
                _ => throw new McpException($"Can't infer a format from '{info.Extension}'. Pass format=ini|json|xml|properties."),
            },
            "ini" or "json" or "xml" or "properties" => format.Trim().ToLowerInvariant(),
            _ => throw new McpException("format must be auto, ini, json, xml or properties."),
        };

        var text = ReadAllTextDetectingEncoding(target.FullPath);
        var outcome = resolvedFormat switch
        {
            "ini" => ConfigParsers.ParseIni(text),
            "json" => ConfigParsers.ParseJson(text, includeData && text.Length <= 2_000_000),
            "xml" => ConfigParsers.ParseXml(text, options.MaxReadBytes),
            _ => ConfigParsers.ParseProperties(text),
        };

        audit.Write("parse_config_file", $"{target.Display} as {resolvedFormat} (valid={outcome.Valid})");
        return new ParsedConfig(target.Root.Name, target.RelativePath, resolvedFormat, outcome.Valid,
            outcome.Issues.Select(i => new ConfigIssue(i.Severity, i.Message, i.Line, i.Column)).ToList(),
            outcome.Summary, includeData ? outcome.Data : null);
    });

    [McpServerTool(Name = "identify_file_format", Title = "Identify file format", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Identifies a file by its magic bytes (Unreal .uasset/.pak/.utoc, DDS/PNG textures, Wwise .bnk/.pck, FMOD, Unity bundles, Bethesda archives, ZIP/7z, models, executables...) and returns key header details.")]
    public FormatIdentification IdentifyFileFormat(
        [Description(WorkspaceDescription)] string workspace,
        [Description("File path relative to the workspace root.")] string path) => ToolExecution.Run(audit, "identify_file_format", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        var info = new FileInfo(target.FullPath);
        if (!info.Exists)
        {
            throw new McpException($"File not found: {target.Display}");
        }

        using var stream = OpenRead(target.FullPath);
        var head = new byte[(int)Math.Min(4096, info.Length)];
        stream.ReadExactly(head);

        var tailLength = (int)Math.Min(1024, info.Length);
        var tail = new byte[tailLength];
        stream.Seek(-tailLength, SeekOrigin.End);
        stream.ReadExactly(tail);

        var guess = FormatSniffer.Identify(head, tail, info.Extension, info.Length);
        audit.Write("identify_file_format", $"{target.Display} -> {guess.Format}");
        return new FormatIdentification(target.Root.Name, target.RelativePath, info.Length, guess.Format, guess.Category,
            guess.Confidence, guess.Details, Fmt.Hex(head, 32));
    });

    [McpServerTool(Name = "inspect_unreal_file", Title = "Inspect Unreal container/package", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Reads Unreal Engine headers without extracting anything: .pak footer (version, index, encryption, compression), .utoc header (entries, flags) or .uasset/.umap summary (UE4/UE5 file versions, unversioned/cooked). Also checks sibling .utoc/.ucas/.uexp files.")]
    public object InspectUnrealFile(
        [Description(WorkspaceDescription)] string workspace,
        [Description("Path to a .pak, .utoc, .uasset or .umap file.")] string path) => ToolExecution.Run<object>(audit, "inspect_unreal_file", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        if (!File.Exists(target.FullPath))
        {
            throw new McpException($"File not found: {target.Display}");
        }

        var extension = Path.GetExtension(target.FullPath).ToLowerInvariant();
        var basePath = Path.ChangeExtension(target.FullPath, null);
        using var stream = OpenRead(target.FullPath);

        object result = extension switch
        {
            ".pak" => new
            {
                kind = "pak",
                footer = UnrealFormats.ReadPakFooter(stream),
                ioStore = new { utoc = File.Exists(basePath + ".utoc"), ucas = File.Exists(basePath + ".ucas") },
                patchSuffix = Path.GetFileNameWithoutExtension(target.FullPath).EndsWith("_P", StringComparison.OrdinalIgnoreCase),
                hint = "Encrypted indexes need the game's AES key (not handled here). Mods in ~mods normally end with _P so they mount with patch priority.",
            },
            ".utoc" => new
            {
                kind = "utoc",
                header = UnrealFormats.ReadIoStoreToc(stream),
                siblings = new { pak = File.Exists(basePath + ".pak"), ucas = File.Exists(basePath + ".ucas") },
                hint = "UE5 IoStore mods need the .pak + .utoc + .ucas trio with matching names.",
            },
            ".uasset" or ".umap" => new
            {
                kind = "package",
                summary = UnrealFormats.ReadPackageSummary(stream),
                siblings = new { uexp = File.Exists(basePath + ".uexp"), ubulk = File.Exists(basePath + ".ubulk") },
                hint = "Unversioned packages were cooked; versioned ones with a missing .uexp are usually editor (uncooked) assets.",
            },
            _ => throw new McpException("inspect_unreal_file supports .pak, .utoc, .uasset and .umap."),
        };

        audit.Write("inspect_unreal_file", target.Display);
        return new { workspace = target.Root.Name, path = target.RelativePath, sizeBytes = stream.Length, result };
    });

    [McpServerTool(Name = "compare_directories", Title = "Compare directories", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Diffs two folders (e.g. vanilla vs modded, or two mod versions), possibly in different workspaces. Reports files only on one side and files whose size or content hash differ.")]
    public DirectoryDiff CompareDirectories(
        [Description("Workspace of the left/original folder.")] string leftWorkspace,
        [Description("Left folder path.")] string leftPath,
        [Description("Workspace of the right/modified folder.")] string rightWorkspace,
        [Description("Right folder path.")] string rightPath,
        [Description("Hash files of equal size to detect content changes (slower).")] bool compareContent = true,
        CancellationToken cancellationToken = default) => ToolExecution.Run(audit, "compare_directories", () =>
    {
        var left = guard.Resolve(leftWorkspace, leftPath, AccessKind.Read);
        var right = guard.Resolve(rightWorkspace, rightPath, AccessKind.Read);
        if (!Directory.Exists(left.FullPath) || !Directory.Exists(right.FullPath))
        {
            throw new McpException("Both paths must be existing directories.");
        }

        const int maxFiles = 50_000;
        var leftFiles = Snapshot(left, maxFiles, cancellationToken, out var leftTruncated);
        var rightFiles = Snapshot(right, maxFiles, cancellationToken, out var rightTruncated);

        var onlyLeft = leftFiles.Keys.Where(k => !rightFiles.ContainsKey(k)).Order(StringComparer.OrdinalIgnoreCase).ToList();
        var onlyRight = rightFiles.Keys.Where(k => !leftFiles.ContainsKey(k)).Order(StringComparer.OrdinalIgnoreCase).ToList();
        var changed = new List<string>();
        var identical = 0;

        foreach (var (key, l) in leftFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!rightFiles.TryGetValue(key, out var r))
            {
                continue;
            }

            var differs = l.Length != r.Length
                || (compareContent && l.Length <= options.MaxCopyBytes && Hashing.ComputeFile(l.FullName) != Hashing.ComputeFile(r.FullName));

            if (differs)
            {
                changed.Add(key);
            }
            else
            {
                identical++;
            }
        }

        changed.Sort(StringComparer.OrdinalIgnoreCase);
        audit.Write("compare_directories", $"{left.Display} vs {right.Display}: +{onlyRight.Count} -{onlyLeft.Count} ~{changed.Count}");

        const int cap = 2000;
        return new DirectoryDiff(left.Display, right.Display, leftFiles.Count, rightFiles.Count,
            onlyLeft.Take(cap).ToList(), onlyRight.Take(cap).ToList(), changed.Take(cap).ToList(), identical,
            leftTruncated || rightTruncated || onlyLeft.Count > cap || onlyRight.Count > cap || changed.Count > cap);
    });

    [McpServerTool(Name = "compute_file_hashes", Title = "Compute file hashes", ReadOnly = false, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Hashes files in a folder (sha256 default) for integrity checks or release manifests. Optionally writes a SHA256SUMS-style manifest into a ReadWrite workspace.")]
    public HashReport ComputeFileHashes(
        [Description(WorkspaceDescription)] string workspace,
        [Description("Folder (or single file) relative to the workspace root.")] string path = "",
        [Description("File name wildcard, e.g. *.pak.")] string pattern = "*",
        [Description("sha256, sha512, sha1 or md5.")] string algorithm = "sha256",
        [Description("Optional manifest path to write (same workspace, must be ReadWrite).")] string? writeManifestTo = null,
        CancellationToken cancellationToken = default) => ToolExecution.Run(audit, "compute_file_hashes", () =>
    {
        var target = guard.Resolve(workspace, path, AccessKind.Read);
        var results = new List<FileHash>();
        var truncated = false;
        var limit = options.MaxListEntries;

        IEnumerable<(FileInfo Info, string Relative)> candidates;
        if (File.Exists(target.FullPath))
        {
            candidates = new List<(FileInfo Info, string Relative)> { (new FileInfo(target.FullPath), target.RelativePath) };
        }
        else if (Directory.Exists(target.FullPath))
        {
            candidates = WorkspaceWalker.Walk(target.Root, target.FullPath, recursive: true, cancellationToken: cancellationToken)
                .Where(e => e.Info is FileInfo && !e.IsLink && FileSystemTools.MatchesPattern(pattern, e.Info.Name))
                .Select(e => ((FileInfo)e.Info, e.RelativePath));
        }
        else
        {
            throw new McpException($"Not found: {target.Display}");
        }

        foreach (var (info, relative) in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (results.Count >= limit)
            {
                truncated = true;
                break;
            }

            if (info.Length > options.MaxCopyBytes)
            {
                continue;
            }

            results.Add(new FileHash(relative, info.Length, Hashing.ComputeFile(info.FullName, algorithm)));
        }

        string? manifest = null;
        if (!string.IsNullOrWhiteSpace(writeManifestTo))
        {
            var output = guard.Resolve(workspace, writeManifestTo, AccessKind.Write);
            var builder = new StringBuilder();
            foreach (var file in results)
            {
                builder.Append(file.Hash).Append("  ").Append(file.Path).Append('\n');
            }

            Directory.CreateDirectory(Path.GetDirectoryName(output.FullPath)!);
            File.WriteAllText(output.FullPath, builder.ToString(), new UTF8Encoding(false));
            manifest = output.RelativePath;
        }

        audit.Write("compute_file_hashes", $"{target.Display} ({results.Count} files, {algorithm})");
        return new HashReport(target.Root.Name, algorithm.ToLowerInvariant(), results.Count, truncated, results, manifest);
    });

    // ---------------------------------------------------------------------------------------------------------------

    private static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024);

    private static string ReadAllTextDetectingEncoding(string path)
    {
        using var reader = new StreamReader(OpenRead(path), new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    private static Dictionary<string, FileInfo> Snapshot(ResolvedPath root, int maxFiles, CancellationToken cancellationToken, out bool truncated)
    {
        truncated = false;
        var map = new Dictionary<string, FileInfo>(StringComparer.OrdinalIgnoreCase);
        var prefixLength = root.RelativePath.Length == 0 ? 0 : root.RelativePath.Length + 1;

        foreach (var entry in WorkspaceWalker.Walk(root.Root, root.FullPath, recursive: true, cancellationToken: cancellationToken))
        {
            if (entry.Info is not FileInfo file || entry.IsLink)
            {
                continue;
            }

            if (map.Count >= maxFiles)
            {
                truncated = true;
                break;
            }

            map[entry.RelativePath[prefixLength..]] = file;
        }

        return map;
    }

    private static void BuildTree(DirectoryInfo directory, string indent, int depth, int maxDepth, List<string> lines, int maxLines)
    {
        foreach (var child in WorkspaceWalker.ListChildren(directory))
        {
            if (lines.Count >= maxLines)
            {
                lines.Add(indent + "… (tree truncated)");
                return;
            }

            var isLink = child.LinkTarget is not null;
            if (child is DirectoryInfo sub)
            {
                lines.Add($"{indent}{sub.Name}/{(isLink ? "  [link, not followed]" : "")}");
                if (!isLink && depth < maxDepth)
                {
                    BuildTree(sub, indent + "  ", depth + 1, maxDepth, lines, maxLines);
                    if (lines.Count > maxLines)
                    {
                        return;
                    }
                }
            }
            else if (child is FileInfo file)
            {
                lines.Add($"{indent}{file.Name}  ({Fmt.Size(file.Length)})");
            }
        }
    }

    private static List<DetectedEcosystem> DetectEcosystems(List<(FileInfo Info, string Relative)> files, HashSet<string> directoryNames, List<string> warnings)
    {
        var result = new List<DetectedEcosystem>();
        var byExtension = files.ToLookup(f => f.Info.Extension.ToLowerInvariant());
        var names = new HashSet<string>(files.Select(f => f.Info.Name), StringComparer.OrdinalIgnoreCase);
        bool Has(params string[] extensions) => extensions.Any(e => byExtension[e].Any());

        // ---- Unreal Engine ----
        if (Has(".pak", ".utoc", ".ucas", ".uasset", ".umap", ".uproject", ".uplugin") || directoryNames.Contains("~mods") || directoryNames.Contains("LogicMods"))
        {
            var evidence = new List<string>();
            foreach (var ext in new[] { ".pak", ".utoc", ".ucas", ".uasset", ".umap", ".uproject", ".uplugin" })
            {
                var count = byExtension[ext].Count();
                if (count > 0)
                {
                    evidence.Add($"{count} {ext}");
                }
            }

            if (directoryNames.Contains("~mods")) evidence.Add("~mods folder");
            if (directoryNames.Contains("LogicMods")) evidence.Add("LogicMods folder (Blueprint/UE4SS mods)");
            result.Add(new DetectedEcosystem("Unreal Engine", Has(".pak", ".utoc", ".uasset") ? "high" : "medium", evidence));

            foreach (var (pak, relative) in byExtension[".pak"])
            {
                var basePath = Path.ChangeExtension(pak.FullName, null);
                var hasUtoc = File.Exists(basePath + ".utoc");
                var hasUcas = File.Exists(basePath + ".ucas");
                if (hasUtoc != hasUcas)
                {
                    warnings.Add($"IoStore container incomplete for {relative}: .utoc={hasUtoc}, .ucas={hasUcas}.");
                }

                var inModsFolder = relative.Contains("~mods/", StringComparison.OrdinalIgnoreCase);
                if (inModsFolder && !Path.GetFileNameWithoutExtension(pak.Name).EndsWith("_P", StringComparison.OrdinalIgnoreCase))
                {
                    warnings.Add($"{relative} is in ~mods but its name doesn't end with _P; it may not override base game content.");
                }
            }

            foreach (var (utoc, relative) in byExtension[".utoc"])
            {
                if (!File.Exists(Path.ChangeExtension(utoc.FullName, ".pak")))
                {
                    warnings.Add($"{relative} has no matching .pak; UE5 needs the .pak stub to mount an IoStore container.");
                }
            }

            var orphanAssets = byExtension[".uasset"].Where(a => !File.Exists(Path.ChangeExtension(a.Info.FullName, ".uexp"))).Take(5).ToList();
            if (orphanAssets.Count > 0)
            {
                warnings.Add($"{orphanAssets.Count}+ .uasset files have no .uexp (e.g. {orphanAssets[0].Relative}); these look like uncooked editor assets.");
            }
        }

        // ---- Unity ----
        if (Has(".assets", ".bundle", ".unity3d") || directoryNames.Contains("BepInEx") || names.Contains("doorstop_config.ini") || names.Contains("UnityPlayer.dll"))
        {
            var evidence = new List<string>();
            if (directoryNames.Contains("BepInEx")) evidence.Add("BepInEx folder");
            if (names.Contains("doorstop_config.ini")) evidence.Add("doorstop_config.ini (Unity Doorstop loader)");
            if (names.Contains("UnityPlayer.dll")) evidence.Add("UnityPlayer.dll");
            if (Has(".assets", ".bundle", ".unity3d")) evidence.Add("Unity asset files");
            result.Add(new DetectedEcosystem("Unity", "high", evidence));
        }

        // ---- Minecraft resource / shader packs ----
        var shaderSources = files.Count(f => f.Info.Extension.ToLowerInvariant() is ".fsh" or ".vsh" or ".gsh" or ".csh" or ".glsl");
        if (names.Contains("pack.mcmeta") || (directoryNames.Contains("shaders") && shaderSources > 0))
        {
            var evidence = new List<string>();
            if (names.Contains("pack.mcmeta")) evidence.Add("pack.mcmeta");
            if (shaderSources > 0) evidence.Add($"{shaderSources} GLSL shader sources");
            if (names.Contains("shaders.properties")) evidence.Add("shaders.properties (OptiFine/Iris)");
            var isShaderPack = directoryNames.Contains("shaders") && shaderSources > 0;
            result.Add(new DetectedEcosystem(isShaderPack ? "Minecraft shader pack (OptiFine/Iris)" : "Minecraft resource/data pack", "high", evidence));

            if (isShaderPack && !names.Contains("shaders.properties"))
            {
                warnings.Add("Shader pack has no shaders.properties; options, profiles and custom uniforms won't be available.");
            }

            foreach (var mcmeta in files.Where(f => f.Info.Name.Equals("pack.mcmeta", StringComparison.OrdinalIgnoreCase)))
            {
                try
                {
                    var node = JsonNode.Parse(File.ReadAllText(mcmeta.Info.FullName));
                    if (node?["pack"]?["pack_format"] is null)
                    {
                        warnings.Add($"{mcmeta.Relative} is missing pack.pack_format.");
                    }
                }
                catch (System.Text.Json.JsonException ex)
                {
                    warnings.Add($"{mcmeta.Relative} is not valid JSON: {ex.Message}");
                }
            }
        }

        // ---- Bethesda ----
        if (Has(".esp", ".esm", ".esl", ".ba2", ".bsa"))
        {
            result.Add(new DetectedEcosystem("Bethesda (Creation Engine)", "high",
                new[] { ".esp", ".esm", ".esl", ".ba2", ".bsa" }.Where(e => byExtension[e].Any()).Select(e => $"{byExtension[e].Count()} {e}").ToList()));
        }

        // ---- Source engine ----
        if (Has(".vpk", ".vmt", ".vtf", ".bsp") || names.Contains("addoninfo.txt") || names.Contains("gameinfo.txt"))
        {
            var evidence = new[] { ".vpk", ".vmt", ".vtf", ".bsp" }.Where(e => byExtension[e].Any()).Select(e => $"{byExtension[e].Count()} {e}").ToList();
            if (names.Contains("addoninfo.txt")) evidence.Add("addoninfo.txt");
            if (names.Contains("gameinfo.txt")) evidence.Add("gameinfo.txt");
            result.Add(new DetectedEcosystem("Source engine", "medium", evidence));
        }

        // ---- Generic mod metadata ----
        var manifests = files.Where(f => f.Info.Name.ToLowerInvariant() is "modinfo.json" or "mod.json" or "manifest.json" or "info.json" or "mod.info" or "modinfo.xml")
            .Select(f => f.Relative).Take(10).ToList();
        if (manifests.Count > 0)
        {
            result.Add(new DetectedEcosystem("Mod metadata", "medium", manifests));
        }

        if (result.Count == 0)
        {
            result.Add(new DetectedEcosystem("Unknown", "low", ["No known modding layout detected."]));
        }

        return result;
    }
}
