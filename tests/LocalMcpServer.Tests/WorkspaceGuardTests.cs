using LocalMcpServer.Configuration;
using LocalMcpServer.Security;
using ModelContextProtocol;

namespace LocalMcpServer.Tests;

public sealed class WorkspaceGuardTests
{
    [Theory]
    [InlineData(@"..\outside.txt")]
    [InlineData("../outside.txt")]
    [InlineData(@"sub\..\..\outside.txt")]
    [InlineData(@"C:\Windows\win.ini")]
    [InlineData(@"\Windows\win.ini")]
    [InlineData(@"\\server\share\file.txt")]
    [InlineData("file.txt:hidden-stream")]
    [InlineData("NUL")]
    [InlineData("con.txt")]
    [InlineData(@"sub\COM1.log")]
    [InlineData("trailingdot.")]
    [InlineData(@"trailingspace \file.txt")]
    [InlineData("bad<name>.txt")]
    public void Rejects_paths_that_escape_or_abuse_windows_semantics(string path)
    {
        using var ws = new TempWorkspace();
        Assert.Throws<McpException>(() => ws.Guard.Resolve("ws", path, AccessKind.Read));
    }

    [Fact]
    public void Resolves_nested_relative_paths_inside_root()
    {
        using var ws = new TempWorkspace();
        ws.Write(@"Content\Paks\~mods\MyMod_P.pak");

        var resolved = ws.Guard.Resolve("ws", "Content/Paks/~mods/MyMod_P.pak", AccessKind.Read);

        Assert.Equal("Content/Paks/~mods/MyMod_P.pak", resolved.RelativePath);
        Assert.StartsWith(ws.Root, resolved.FullPath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Empty_path_resolves_to_root_for_reads_but_root_is_not_writable()
    {
        using var ws = new TempWorkspace();
        Assert.True(ws.Guard.Resolve("ws", "", AccessKind.Read).IsRoot);
        Assert.Throws<McpException>(() => ws.Guard.Resolve("ws", "", AccessKind.Write));
    }

    [Fact]
    public void Read_only_workspace_rejects_writes()
    {
        using var ws = new TempWorkspace(WorkspaceAccess.ReadOnly);
        Assert.Throws<McpException>(() => ws.Guard.Resolve("ws", "new.txt", AccessKind.Write));
    }

    [Theory]
    [InlineData("payload.exe")]
    [InlineData("script.PS1")]
    [InlineData(@"deep\run.bat")]
    public void Blocked_extensions_cannot_be_written(string path)
    {
        using var ws = new TempWorkspace();
        Assert.Throws<McpException>(() => ws.Guard.Resolve("ws", path, AccessKind.Write));
    }

    [Fact]
    public void Unknown_workspace_is_rejected()
    {
        using var ws = new TempWorkspace();
        Assert.Throws<McpException>(() => ws.Guard.Resolve("nope", "a.txt", AccessKind.Read));
    }

    [Fact]
    public void Drive_roots_and_missing_directories_are_rejected_as_workspaces()
    {
        Assert.NotNull(WorkspaceGuard.ValidateRootLocation(Path.GetPathRoot(Path.GetTempPath())!, WorkspaceAccess.ReadOnly));
        Assert.NotNull(WorkspaceGuard.ValidateRootLocation(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")), WorkspaceAccess.ReadOnly));
    }

    [Fact]
    public void Settings_directory_can_never_be_a_workspace()
    {
        Directory.CreateDirectory(SettingsStore.AppDataDirectory);
        Assert.NotNull(WorkspaceGuard.ValidateRootLocation(SettingsStore.AppDataDirectory, WorkspaceAccess.ReadOnly));
    }

    [Fact]
    public void Junction_pointing_outside_is_rejected()
    {
        using var ws = new TempWorkspace();
        var outside = Path.Combine(Path.GetTempPath(), "localmcp-tests", "outside-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "secret");

        try
        {
            Directory.CreateSymbolicLink(Path.Combine(ws.Root, "escape"), outside);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return; // Symlink creation needs Developer Mode or admin rights; skip on locked-down machines.
        }

        try
        {
            Assert.Throws<McpException>(() => ws.Guard.Resolve("ws", "escape/secret.txt", AccessKind.Read));
        }
        finally
        {
            Directory.Delete(Path.Combine(ws.Root, "escape"));
            Directory.Delete(outside, recursive: true);
        }
    }
}
