using LocalMcpServer.Security;

namespace LocalMcpServer.Tools;

internal sealed record WalkEntry(FileSystemInfo Info, string RelativePath, int Depth, bool IsLink);

/// <summary>
/// Depth-first directory walk that never follows symbolic links or junctions,
/// so recursion can't wander outside the workspace even if a link slipped in.
/// </summary>
internal static class WorkspaceWalker
{
    private static readonly EnumerationOptions Options = new()
    {
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        AttributesToSkip = 0,
        ReturnSpecialDirectories = false,
    };

    public static IEnumerable<WalkEntry> Walk(WorkspaceRoot root, string startDirectory, bool recursive, int maxDepth = 64, CancellationToken cancellationToken = default)
    {
        var stack = new Stack<(DirectoryInfo Directory, int Depth)>();
        stack.Push((new DirectoryInfo(startDirectory), 0));

        while (stack.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (directory, depth) = stack.Pop();

            var children = ListChildren(directory);
            var subdirectories = new List<DirectoryInfo>();

            foreach (var child in children)
            {
                var isLink = child.LinkTarget is not null;
                yield return new WalkEntry(child, WorkspaceGuard.ToRelative(root, child.FullName), depth + 1, isLink);

                if (recursive && child is DirectoryInfo sub && !isLink && depth + 1 < maxDepth)
                {
                    subdirectories.Add(sub);
                }
            }

            for (var i = subdirectories.Count - 1; i >= 0; i--)
            {
                stack.Push((subdirectories[i], depth + 1));
            }
        }
    }

    public static List<FileSystemInfo> ListChildren(DirectoryInfo directory)
    {
        try
        {
            return directory.EnumerateFileSystemInfos("*", Options)
                .OrderBy(c => c is FileInfo)
                .ThenBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
