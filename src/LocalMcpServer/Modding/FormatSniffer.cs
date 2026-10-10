using System.Buffers.Binary;
using System.Text;

namespace LocalMcpServer.Modding;

public sealed record FormatGuess(string Format, string Category, string Confidence, Dictionary<string, object?> Details);

/// <summary>Magic-byte based identification of common game/modding file formats.</summary>
public static class FormatSniffer
{
    public const uint UnrealPackageTag = 0x9E2A83C1;
    public const uint UnrealPakMagic = 0x5A6F12E1;
    public static readonly byte[] IoStoreTocMagic = "-==--==--==--==-"u8.ToArray();

    public static bool LooksBinary(ReadOnlySpan<byte> head)
    {
        if (head.Length == 0)
        {
            return false;
        }

        if (head.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }) || head.StartsWith(new byte[] { 0xFF, 0xFE }) || head.StartsWith(new byte[] { 0xFE, 0xFF }))
        {
            return false;
        }

        var control = 0;
        foreach (var b in head)
        {
            if (b == 0)
            {
                return true;
            }

            if (b < 7 || (b > 13 && b < 32 && b != 27))
            {
                control++;
            }
        }

        return control * 10 > head.Length;
    }

    public static FormatGuess Identify(ReadOnlySpan<byte> head, ReadOnlySpan<byte> tail, string extension, long length)
    {
        var details = new Dictionary<string, object?>();
        var ext = extension.ToLowerInvariant();

        FormatGuess Hit(string format, string category, string confidence = "high") => new(format, category, confidence, details);

        bool Starts(ReadOnlySpan<byte> h, string ascii) => h.StartsWith(Encoding.ASCII.GetBytes(ascii));

        if (head.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(head) == UnrealPackageTag)
        {
            return Hit("Unreal Engine package (.uasset/.umap)", "unreal");
        }

        if (head.StartsWith(IoStoreTocMagic))
        {
            return Hit("Unreal Engine IoStore table of contents (.utoc)", "unreal");
        }

        if (FindPakMagic(tail) >= 0)
        {
            return Hit("Unreal Engine PAK archive", "unreal");
        }

        if (head.StartsWith(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }))
        {
            if (head.Length >= 24)
            {
                details["width"] = BinaryPrimitives.ReadUInt32BigEndian(head[16..]);
                details["height"] = BinaryPrimitives.ReadUInt32BigEndian(head[20..]);
            }

            return Hit("PNG image", "texture");
        }

        if (Starts(head, "DDS ") && head.Length >= 88)
        {
            details["height"] = BinaryPrimitives.ReadUInt32LittleEndian(head[12..]);
            details["width"] = BinaryPrimitives.ReadUInt32LittleEndian(head[16..]);
            details["mipMaps"] = BinaryPrimitives.ReadUInt32LittleEndian(head[28..]);
            var fourCc = Encoding.ASCII.GetString(head.Slice(84, 4)).TrimEnd('\0');
            details["fourCC"] = string.IsNullOrWhiteSpace(fourCc) ? null : fourCc;
            return Hit("DirectDraw Surface texture (DDS)", "texture");
        }

        if (head.StartsWith(new byte[] { 0xFF, 0xD8, 0xFF })) return Hit("JPEG image", "texture");
        if (Starts(head, "VTF\0")) return Hit("Valve Texture Format (VTF)", "texture");
        if (Starts(head, "#?RADIANCE") || Starts(head, "#?RGBE")) return Hit("Radiance HDR image", "texture");
        if (Starts(head, "BM") && ext == ".bmp") return Hit("Bitmap image", "texture");
        if (head.Length >= 18 && ext == ".tga") return Hit("Truevision TGA image", "texture", "medium");

        if (Starts(head, "PK\x03\x04") || Starts(head, "PK\x05\x06"))
        {
            return Hit(ext switch
            {
                ".jar" => "Java archive (JAR)",
                ".mcpack" or ".mcaddon" => "Minecraft Bedrock pack (ZIP)",
                _ => "ZIP archive",
            }, "archive");
        }

        if (head.StartsWith(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })) return Hit("7-Zip archive", "archive");
        if (Starts(head, "Rar!\x1A\x07")) return Hit("RAR archive", "archive");
        if (Starts(head, "UnityFS")) return Hit("Unity asset bundle", "unity");
        if (Starts(head, "BSA\0")) return Hit("Bethesda archive (BSA)", "bethesda");
        if (Starts(head, "BTDX")) return Hit("Bethesda archive (BA2)", "bethesda");
        if (Starts(head, "TES4") || Starts(head, "TES3")) return Hit("Bethesda plugin (ESP/ESM/ESL)", "bethesda");
        if (head.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(head) == 0x55AA1234) return Hit("Valve pak (VPK)", "source");
        if (Starts(head, "BKHD")) return Hit("Wwise SoundBank (.bnk)", "audio");
        if (Starts(head, "AKPK")) return Hit("Wwise file package (.pck)", "audio");
        if (Starts(head, "FSB5")) return Hit("FMOD sound bank (FSB5)", "audio");
        if (Starts(head, "OggS")) return Hit("Ogg container (Vorbis/Opus)", "audio");
        if (Starts(head, "fLaC")) return Hit("FLAC audio", "audio");
        if (Starts(head, "RIFF") && head.Length >= 12)
        {
            var kind = Encoding.ASCII.GetString(head.Slice(8, 4));
            return Hit(kind switch
            {
                "WAVE" => "WAV audio",
                "WEBP" => "WebP image",
                "AVI " => "AVI video",
                _ => $"RIFF container ({kind})",
            }, kind == "WAVE" ? "audio" : "media");
        }

        if (Starts(head, "glTF")) return Hit("glTF binary model (GLB)", "model");
        if (Starts(head, "Kaydara FBX Binary")) return Hit("Autodesk FBX (binary)", "model");
        if (Starts(head, "MZ")) return Hit("Windows PE executable/library", "executable");
        if (head.StartsWith(new byte[] { 0x7F, 0x45, 0x4C, 0x46 })) return Hit("ELF executable", "executable");
        if (Starts(head, "SQLite format 3\0")) return Hit("SQLite database", "data");

        if (!LooksBinary(head))
        {
            var text = DecodeText(head).TrimStart('\uFEFF', ' ', '\t', '\r', '\n');
            if (text.StartsWith('{') || text.StartsWith('[') && ext is ".json" or ".mcmeta" or ".uplugin" or ".uproject")
            {
                return Hit("JSON text", "config", "medium");
            }

            if (text.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) || (text.StartsWith('<') && ext is ".xml" or ".config"))
            {
                return Hit("XML text", "config", "medium");
            }

            if (text.StartsWith('[') || ext is ".ini" or ".cfg")
            {
                return Hit("INI-style configuration", "config", "medium");
            }

            if (ext is ".fsh" or ".vsh" or ".gsh" or ".csh" or ".glsl" or ".hlsl" or ".usf" or ".ush")
            {
                return Hit("Shader source", "shader", "medium");
            }

            if (ext == ".properties")
            {
                return Hit("Java .properties", "config", "medium");
            }

            return Hit("Plain text", "text", "low");
        }

        details["note"] = length == 0 ? "empty file" : "no known signature";
        return Hit(ext switch
        {
            ".uexp" => "Unreal Engine export data (.uexp)",
            ".ubulk" => "Unreal Engine bulk data (.ubulk)",
            ".ucas" => "Unreal Engine IoStore container data (.ucas)",
            ".assets" => "Unity serialized assets",
            _ => "Unknown binary",
        }, ext is ".uexp" or ".ubulk" or ".ucas" ? "unreal" : "binary", ext is ".uexp" or ".ubulk" or ".ucas" ? "medium" : "low");
    }

    public static int FindPakMagic(ReadOnlySpan<byte> tail)
    {
        for (var i = tail.Length - 4; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(tail[i..]) == UnrealPakMagic)
            {
                return i;
            }
        }

        return -1;
    }

    private static string DecodeText(ReadOnlySpan<byte> head)
    {
        if (head.StartsWith(new byte[] { 0xFF, 0xFE }))
        {
            return Encoding.Unicode.GetString(head);
        }

        return Encoding.UTF8.GetString(head);
    }
}
