using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using LocalMcpServer.Configuration;
using LocalMcpServer.Infrastructure;
using Microsoft.Win32;
using ModelContextProtocol.Server;

namespace LocalMcpServer.Tools;

/// <summary>Read-only, structured system information. Never spawns processes and never exposes environment variables.</summary>
[McpServerToolType]
public sealed partial class SystemInfoTools(ServerOptions options, AuditLog audit)
{
    [McpServerTool(Name = "get_system_info", Title = "System information", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Returns structured hardware/OS information: Windows edition and build, CPU, memory, GPUs, fixed drives and server runtime. Machine and user names are only included if enabled in settings.")]
    public SystemInfo GetSystemInfo() => ToolExecution.Run(audit, "get_system_info", () =>
    {
        var info = new SystemInfo(
            ReadOs(),
            new CpuInfo(ReadCpuName(), Environment.ProcessorCount, RuntimeInformation.OSArchitecture.ToString()),
            ReadMemory(),
            ReadGpus(),
            ReadDrives(),
            new ServerRuntimeInfo(
                AppInfo.Version,
                RuntimeInformation.FrameworkDescription,
                RuntimeInformation.ProcessArchitecture.ToString(),
                Environment.ProcessId,
                DateTimeOffset.Now - AppInfo.StartedAt,
                AppInfo.IsElevated()),
            options.IncludeMachineIdentifiers
                ? new IdentityInfo(Environment.MachineName, Environment.UserName, Environment.UserDomainName)
                : null);

        audit.Write("get_system_info", "ok");
        return info;
    });

    [McpServerTool(Name = "detect_dev_tools", Title = "Detect developer tools", ReadOnly = true, Idempotent = true, OpenWorld = false)]
    [Description("Checks PATH for common developer tools (git, dotnet, node, python, cmake...) without executing them, and reports Steam library folders to help locate game installs.")]
    public DevToolReport DetectDevTools() => ToolExecution.Run(audit, "detect_dev_tools", () =>
    {
        string[] candidates = ["git", "dotnet", "node", "npm", "pnpm", "python", "py", "cmake", "ninja", "msbuild", "code", "blender", "7z"];
        var pathDirectories = (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var extensions = (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD;.BAT")
            .Split(';', StringSplitOptions.RemoveEmptyEntries);

        var tools = candidates.Select(name =>
        {
            foreach (var dir in pathDirectories)
            {
                foreach (var ext in extensions)
                {
                    try
                    {
                        var candidate = Path.Combine(dir, name + ext.ToLowerInvariant());
                        if (File.Exists(candidate))
                        {
                            return new DevToolInfo(name, true, candidate);
                        }
                    }
                    catch (ArgumentException)
                    {
                        // Malformed PATH entry.
                    }
                }
            }

            return new DevToolInfo(name, false, null);
        }).ToList();

        var steamPath = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
        var libraries = new List<string>();
        if (!string.IsNullOrEmpty(steamPath))
        {
            steamPath = Path.GetFullPath(steamPath);
            var vdf = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
            if (File.Exists(vdf))
            {
                foreach (Match match in SteamLibraryPath().Matches(File.ReadAllText(vdf)))
                {
                    libraries.Add(match.Groups[1].Value.Replace(@"\\", @"\"));
                }
            }
        }

        audit.Write("detect_dev_tools", $"{tools.Count(t => t.Found)} tools found");
        return new DevToolReport(tools, steamPath, libraries.Distinct(StringComparer.OrdinalIgnoreCase).ToList());
    });

    [GeneratedRegex("\"path\"\\s+\"([^\"]+)\"", RegexOptions.IgnoreCase)]
    private static partial Regex SteamLibraryPath();

    private static OsInfo ReadOs()
    {
        const string key = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        var product = Registry.GetValue(key, "ProductName", null) as string ?? "Windows";
        var displayVersion = Registry.GetValue(key, "DisplayVersion", null) as string;
        var currentBuild = Registry.GetValue(key, "CurrentBuild", null) as string ?? Environment.OSVersion.Version.Build.ToString();
        var ubr = Registry.GetValue(key, "UBR", null);

        // ProductName still says "Windows 10" on Windows 11; build 22000+ is Windows 11.
        if (int.TryParse(currentBuild, out var build) && build >= 22000)
        {
            product = product.Replace("Windows 10", "Windows 11", StringComparison.Ordinal);
        }

        return new OsInfo(product, displayVersion, ubr is null ? currentBuild : $"{currentBuild}.{ubr}",
            RuntimeInformation.OSDescription, RuntimeInformation.OSArchitecture.ToString());
    }

    private static string? ReadCpuName() =>
        (Registry.GetValue(@"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString", null) as string)?.Trim();

    private static MemoryInfo ReadMemory()
    {
        var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
        return GlobalMemoryStatusEx(ref status)
            ? new MemoryInfo(status.TotalPhys, status.AvailPhys, status.MemoryLoad)
            : new MemoryInfo((ulong)GC.GetGCMemoryInfo().TotalAvailableMemoryBytes, 0, 0);
    }

    private static List<GpuInfo> ReadGpus()
    {
        const string displayClass = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
        var gpus = new List<GpuInfo>();
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(displayClass);
            if (root is null)
            {
                return gpus;
            }

            foreach (var name in root.GetSubKeyNames().Where(n => n.Length == 4 && n.All(char.IsAsciiDigit)))
            {
                try
                {
                    using var adapter = root.OpenSubKey(name);
                    if (adapter?.GetValue("DriverDesc") is not string description)
                    {
                        continue;
                    }

                    var memory = ReadAdapterMemory(adapter);

                    gpus.Add(new GpuInfo(description, adapter.GetValue("DriverVersion") as string, memory));
                }
                catch (System.Security.SecurityException)
                {
                    // Some adapter keys are ACL-protected.
                }
            }
        }
        catch (System.Security.SecurityException)
        {
        }

        return gpus.DistinctBy(g => g.Name).ToList();
    }

    private static ulong? ReadAdapterMemory(RegistryKey adapter)
    {
        switch (adapter.GetValue("HardwareInformation.qwMemorySize"))
        {
            case long qword:
                return (ulong)qword;
            case byte[] { Length: >= 8 } qwordBytes:
                return BitConverter.ToUInt64(qwordBytes, 0);
        }

        switch (adapter.GetValue("HardwareInformation.MemorySize"))
        {
            case int dword:
                return (uint)dword;
            case byte[] { Length: >= 4 } dwordBytes:
                return BitConverter.ToUInt32(dwordBytes, 0);
            default:
                return null;
        }
    }

    private static List<DriveDetails> ReadDrives() =>
        DriveInfo.GetDrives()
            .Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable)
            .Select(d =>
            {
                try
                {
                    return d.IsReady
                        ? new DriveDetails(d.Name, d.DriveType.ToString(), d.DriveFormat, d.TotalSize, d.AvailableFreeSpace)
                        : new DriveDetails(d.Name, d.DriveType.ToString(), null, null, null);
                }
                catch (IOException)
                {
                    return new DriveDetails(d.Name, d.DriveType.ToString(), null, null, null);
                }
            })
            .ToList();

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);
}
