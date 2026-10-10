using System.Buffers.Binary;
using System.Text;
using LocalMcpServer.Modding;

namespace LocalMcpServer.Tests;

public sealed class ModdingParserTests
{
    [Fact]
    public void Ini_parser_understands_unreal_array_operators()
    {
        const string ini = """
            ; comment
            [/Script/Engine.Engine]
            bSmoothFrameRate=False
            +ActiveGameNameRedirects=(OldGameName="A",NewGameName="B")
            -ActiveGameNameRedirects=(OldGameName="C",NewGameName="D")
            !ActiveClassRedirects=ClearArray
            .Paths=../../Content
            bSmoothFrameRate=True
            """;

        var outcome = ConfigParsers.ParseIni(ini);
        var sections = Assert.IsType<List<IniSection>>(outcome.Data);

        Assert.True(outcome.Valid);
        var section = Assert.Single(sections);
        Assert.Equal("/Script/Engine.Engine", section.Name);
        Assert.Contains(section.Entries, e => e.Operation == "addUnique" && e.Key == "ActiveGameNameRedirects");
        Assert.Contains(section.Entries, e => e.Operation == "remove");
        Assert.Contains(section.Entries, e => e.Operation == "clear" && e.Key == "ActiveClassRedirects");
        Assert.Contains(section.Entries, e => e.Operation == "add" && e.Key == "Paths");
        Assert.Contains(outcome.Issues, i => i.Message.Contains("more than once"));
    }

    [Fact]
    public void Ini_parser_flags_broken_section_headers()
    {
        var outcome = ConfigParsers.ParseIni("[Broken\nKey=Value");
        Assert.False(outcome.Valid);
    }

    [Fact]
    public void Json_parser_reports_line_of_syntax_errors()
    {
        var outcome = ConfigParsers.ParseJson("{\n  \"pack\": {\n    \"pack_format\": 15,\n  \n", includeData: false);
        Assert.False(outcome.Valid);
        Assert.NotNull(Assert.Single(outcome.Issues).Line);
    }

    [Fact]
    public void Xml_parser_refuses_dtds()
    {
        const string xxe = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///c:/windows/win.ini\">]><x>&e;</x>";
        Assert.False(ConfigParsers.ParseXml(xxe, 1_000_000).Valid);
    }

    [Fact]
    public void Properties_parser_handles_continuations()
    {
        var outcome = ConfigParsers.ParseProperties("screen=SHADOWS \\\n  REFLECTIONS\n# comment\nsliders=SUN_ANGLE");
        var entries = Assert.IsType<List<IniEntry>>(outcome.Data);
        Assert.Equal(2, entries.Count);
        Assert.Equal("SHADOWS REFLECTIONS", entries[0].Value);
    }

    [Fact]
    public void Sniffer_identifies_unreal_package_and_png()
    {
        var uasset = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(uasset, FormatSniffer.UnrealPackageTag);
        Assert.Contains("Unreal Engine package", FormatSniffer.Identify(uasset, uasset, ".uasset", 16).Format);

        byte[] png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, .. "IHDR"u8, 0, 0, 1, 0, 0, 0, 2, 0];
        var guess = FormatSniffer.Identify(png, png, ".png", png.Length);
        Assert.Equal("PNG image", guess.Format);
        Assert.Equal(256u, guess.Details["width"]);
    }

    [Fact]
    public void Pak_footer_is_parsed_from_synthetic_archive()
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[128]);          // fake entry data
        var indexOffset = stream.Position;
        stream.Write(new byte[64]);           // fake index
        stream.Write(new byte[16]);           // encryption key guid (none)
        stream.WriteByte(0);                  // bEncryptedIndex
        Span<byte> buffer = stackalloc byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, FormatSniffer.UnrealPakMagic);
        BinaryPrimitives.WriteInt32LittleEndian(buffer[4..], 11);
        BinaryPrimitives.WriteInt64LittleEndian(buffer[8..], indexOffset);
        BinaryPrimitives.WriteInt64LittleEndian(buffer[16..], 64);
        stream.Write(buffer);
        stream.Write(new byte[20]);           // index SHA1
        var oodle = new byte[32];
        Encoding.ASCII.GetBytes("Oodle").CopyTo(oodle, 0);
        stream.Write(oodle);
        stream.Write(new byte[32 * 4]);       // remaining compression slots

        var footer = UnrealFormats.ReadPakFooter(stream);

        Assert.Equal(11, footer.Version);
        Assert.Equal(indexOffset, footer.IndexOffset);
        Assert.Equal(64, footer.IndexSize);
        Assert.False(footer.IndexEncrypted);
        Assert.Null(footer.EncryptionKeyGuid);
        Assert.Equal("Oodle", Assert.Single(footer.CompressionMethods));
    }

    [Fact]
    public void Uasset_summary_detects_unversioned_ue5_package()
    {
        var header = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(header, FormatSniffer.UnrealPackageTag);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4), -8);   // LegacyFileVersion (UE5)
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8), 864);  // LegacyUE3Version
        // UE4, UE5 and licensee versions left at 0 => unversioned (cooked)

        var summary = UnrealFormats.ReadPackageSummary(new MemoryStream(header));

        Assert.Equal(-8, summary.LegacyFileVersion);
        Assert.Equal(0, summary.FileVersionUe5);
        Assert.True(summary.Unversioned);
    }
}
