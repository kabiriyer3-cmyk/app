namespace LocalMcpServer.Infrastructure;

internal static class Fmt
{
    public static string Size(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0 ? $"{bytes} B" : $"{value:0.##} {units[unit]}";
    }

    public static string Hex(ReadOnlySpan<byte> bytes, int max = 32)
    {
        var slice = bytes.Length > max ? bytes[..max] : bytes;
        return Convert.ToHexString(slice).ToLowerInvariant();
    }
}
