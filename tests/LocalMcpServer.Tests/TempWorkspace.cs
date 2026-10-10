using LocalMcpServer.Configuration;
using LocalMcpServer.Security;

namespace LocalMcpServer.Tests;

internal sealed class TempWorkspace : IDisposable
{
    public TempWorkspace(WorkspaceAccess access = WorkspaceAccess.ReadWrite)
    {
        Root = Path.Combine(Path.GetTempPath(), "localmcp-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
        Options = new ServerOptions
        {
            Workspaces = [new WorkspaceRootOptions { Name = "ws", Path = Root, Access = access }],
        };
        Guard = new WorkspaceGuard(Options);
    }

    public string Root { get; }

    public ServerOptions Options { get; }

    public WorkspaceGuard Guard { get; }

    public string Write(string relative, string content = "x")
    {
        var full = Path.Combine(Root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content);
        return full;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
