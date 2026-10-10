using System.Security.Cryptography;
using ModelContextProtocol;

namespace LocalMcpServer.Infrastructure;

internal static class Hashing
{
    public static string ComputeFile(string path, string algorithm = "sha256")
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        var hash = algorithm.Trim().ToLowerInvariant() switch
        {
            "sha256" => SHA256.HashData(stream),
            "sha512" => SHA512.HashData(stream),
            "sha1" => SHA1.HashData(stream),
            "md5" => MD5.HashData(stream),
            _ => throw new McpException("algorithm must be one of: sha256, sha512, sha1, md5."),
        };
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
