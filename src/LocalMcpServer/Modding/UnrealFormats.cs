using System.Buffers.Binary;
using System.Text;

namespace LocalMcpServer.Modding;

public sealed record PakFooterInfo(
    int Version, string VersionName, long IndexOffset, long IndexSize, bool? IndexEncrypted,
    string? EncryptionKeyGuid, IReadOnlyList<string> CompressionMethods, long FooterOffset);

public sealed record IoStoreTocInfo(
    int Version, uint TocEntryCount, uint CompressedBlockCount, uint CompressionBlockSize,
    string ContainerId, IReadOnlyList<string> Flags, string? EncryptionKeyGuid);

public sealed record UnrealPackageSummary(
    int LegacyFileVersion, int? LegacyUe3Version, int FileVersionUe4, int? FileVersionUe5, int LicenseeVersion,
    bool Unversioned, int? CustomVersionCount);

/// <summary>
/// Best-effort header parsers for Unreal Engine 4/5 containers. They only read headers/footers
/// (never decrypt or extract), which is enough to diagnose most "my mod doesn't load" problems.
/// </summary>
public static class UnrealFormats
{
    private static readonly Dictionary<int, string> PakVersionNames = new()
    {
        [1] = "Initial",
        [2] = "NoTimestamps",
        [3] = "CompressionEncryption",
        [4] = "IndexEncryption",
        [5] = "RelativeChunkOffsets",
        [6] = "DeleteRecords",
        [7] = "EncryptionKeyGuid (UE 4.20+)",
        [8] = "FNameBasedCompressionMethod (UE 4.22+)",
        [9] = "FrozenIndex (UE 4.25)",
        [10] = "PathHashIndex (UE 4.26)",
        [11] = "Fnv64BugFix (UE 4.26+/UE5)",
    };

    public static PakFooterInfo ReadPakFooter(Stream stream)
    {
        var length = stream.Length;
        if (length < 44)
        {
            throw new InvalidDataException("File is too small to be an Unreal PAK archive.");
        }

        var tailSize = (int)Math.Min(length, 1024);
        var tail = new byte[tailSize];
        stream.Seek(-tailSize, SeekOrigin.End);
        stream.ReadExactly(tail);
        var tailStart = length - tailSize;

        for (var i = tailSize - 24; i >= 0; i--)
        {
            var span = tail.AsSpan(i);
            if (BinaryPrimitives.ReadUInt32LittleEndian(span) != FormatSniffer.UnrealPakMagic)
            {
                continue;
            }

            var version = BinaryPrimitives.ReadInt32LittleEndian(span[4..]);
            var indexOffset = BinaryPrimitives.ReadInt64LittleEndian(span[8..]);
            var indexSize = BinaryPrimitives.ReadInt64LittleEndian(span[16..]);

            if (version is < 1 or > 64 || indexOffset < 0 || indexSize <= 0 || indexOffset + indexSize > tailStart + i)
            {
                continue; // Not a plausible footer, keep scanning.
            }

            bool? encrypted = version >= 4 && i >= 1 ? tail[i - 1] != 0 : null;

            string? keyGuid = null;
            if (version >= 7 && i >= 17)
            {
                var guid = tail.AsSpan(i - 17, 16);
                keyGuid = guid.IndexOfAnyExcept((byte)0) < 0 ? null : Convert.ToHexString(guid);
            }

            var methods = new List<string>();
            var namesStart = i + 4 + 4 + 8 + 8 + 20; // magic, version, offset, size, SHA1 index hash
            if (version >= 8)
            {
                for (var n = 0; n < 5 && namesStart + ((n + 1) * 32) <= tailSize; n++)
                {
                    var raw = tail.AsSpan(namesStart + (n * 32), 32);
                    var end = raw.IndexOf((byte)0);
                    var name = Encoding.ASCII.GetString(end >= 0 ? raw[..end] : raw).Trim();
                    if (name.Length > 0 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-'))
                    {
                        methods.Add(name);
                    }
                }
            }

            return new PakFooterInfo(version, PakVersionNames.GetValueOrDefault(version, "Unknown/newer"),
                indexOffset, indexSize, encrypted, keyGuid, methods, tailStart + i);
        }

        throw new InvalidDataException("No Unreal PAK footer found. The file may be truncated, not a .pak, or use a custom/obfuscated layout.");
    }

    public static IoStoreTocInfo ReadIoStoreToc(Stream stream)
    {
        var header = new byte[144];
        var read = stream.ReadAtLeast(header, 96, throwOnEndOfStream: false);
        if (read < 96 || !header.AsSpan().StartsWith(FormatSniffer.IoStoreTocMagic))
        {
            throw new InvalidDataException("Not an Unreal IoStore .utoc file (magic mismatch).");
        }

        var span = header.AsSpan();
        var flagsByte = span[80];
        var flags = new List<string>();
        if ((flagsByte & 0x01) != 0) flags.Add("Compressed");
        if ((flagsByte & 0x02) != 0) flags.Add("Encrypted");
        if ((flagsByte & 0x04) != 0) flags.Add("Signed");
        if ((flagsByte & 0x08) != 0) flags.Add("Indexed");
        if ((flagsByte & 0x10) != 0) flags.Add("OnDemand");

        var guid = span.Slice(64, 16);
        return new IoStoreTocInfo(
            span[16],
            BinaryPrimitives.ReadUInt32LittleEndian(span[24..]),
            BinaryPrimitives.ReadUInt32LittleEndian(span[28..]),
            BinaryPrimitives.ReadUInt32LittleEndian(span[44..]),
            BinaryPrimitives.ReadUInt64LittleEndian(span[56..]).ToString("X16"),
            flags,
            guid.IndexOfAnyExcept((byte)0) < 0 ? null : Convert.ToHexString(guid));
    }

    public static UnrealPackageSummary ReadPackageSummary(Stream stream)
    {
        var header = new byte[64];
        var read = stream.ReadAtLeast(header, 20, throwOnEndOfStream: false);
        if (read < 20 || BinaryPrimitives.ReadUInt32LittleEndian(header) != FormatSniffer.UnrealPackageTag)
        {
            throw new InvalidDataException("Not a versioned Unreal package (missing 0x9E2A83C1 tag). Zen/IoStore packages extracted from .ucas don't carry this header.");
        }

        var offset = 4;
        int Next()
        {
            var value = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(offset));
            offset += 4;
            return value;
        }

        var legacy = Next();
        int? ue3 = legacy != -4 ? Next() : null;
        var ue4 = Next();
        int? ue5 = legacy <= -8 ? Next() : null;
        var licensee = Next();
        int? customCount = offset + 4 <= read ? Next() : null;

        var unversioned = ue4 == 0 && (ue5 ?? 0) == 0 && licensee == 0;
        return new UnrealPackageSummary(legacy, ue3, ue4, ue5, licensee, unversioned, customCount);
    }
}
