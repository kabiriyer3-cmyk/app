using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;

namespace LocalMcpServer.Modding;

public sealed record IniEntry(string Key, string Value, string Operation, int Line);

public sealed record IniSection(string Name, int Line, List<IniEntry> Entries);

public sealed record ParseIssue(string Severity, string Message, long? Line, long? Column);

public sealed record ParseOutcome(bool Valid, List<ParseIssue> Issues, object? Summary, object? Data);

/// <summary>Tolerant parsers for configuration formats commonly found in mods.</summary>
public static class ConfigParsers
{
    /// <summary>
    /// Parses INI files including Unreal Engine array operators:
    /// '+' add unique, '.' add, '-' remove, '!' clear. Comments start with ';' or '#'.
    /// </summary>
    public static ParseOutcome ParseIni(string text)
    {
        var issues = new List<ParseIssue>();
        var sections = new List<IniSection>();
        IniSection? current = null;
        var lines = text.Replace("\r\n", "\n").Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var lineNumber = i + 1;
            var line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith('['))
            {
                if (!line.EndsWith(']'))
                {
                    issues.Add(new ParseIssue("error", "Unterminated section header.", lineNumber, null));
                    continue;
                }

                current = new IniSection(line[1..^1].Trim(), lineNumber, []);
                if (sections.Any(s => s.Name.Equals(current.Name, StringComparison.OrdinalIgnoreCase)))
                {
                    issues.Add(new ParseIssue("info", $"Section [{current.Name}] appears more than once; engines usually merge them.", lineNumber, null));
                }

                sections.Add(current);
                continue;
            }

            var separator = line.IndexOf('=');
            var rawKey = separator >= 0 ? line[..separator].Trim() : line;
            var value = separator >= 0 ? line[(separator + 1)..].Trim() : "";

            var operation = rawKey.Length > 0 ? rawKey[0] switch
            {
                '+' => "addUnique",
                '.' => "add",
                '-' => "remove",
                '!' => "clear",
                _ => "set",
            } : "set";

            var key = operation == "set" ? rawKey : rawKey[1..].Trim();
            if (key.Length == 0)
            {
                issues.Add(new ParseIssue("error", "Entry has an empty key.", lineNumber, null));
                continue;
            }

            if (separator < 0 && operation != "clear")
            {
                issues.Add(new ParseIssue("warning", $"'{line}' has no '=' and will likely be ignored.", lineNumber, null));
            }

            if (current is null)
            {
                issues.Add(new ParseIssue("warning", "Entry appears before any [Section] header.", lineNumber, null));
                current = new IniSection("", lineNumber, []);
                sections.Add(current);
            }

            if (operation == "set" && current.Entries.Any(e => e.Operation == "set" && e.Key.Equals(key, StringComparison.OrdinalIgnoreCase)))
            {
                issues.Add(new ParseIssue("info", $"Key '{key}' is set more than once in [{current.Name}]; the last value usually wins.", lineNumber, null));
            }

            current.Entries.Add(new IniEntry(key, value, operation, lineNumber));
        }

        var summary = new
        {
            sections = sections.Count,
            entries = sections.Sum(s => s.Entries.Count),
            arrayOperations = sections.Sum(s => s.Entries.Count(e => e.Operation != "set")),
        };

        return new ParseOutcome(!issues.Any(i => i.Severity == "error"), issues, summary, sections);
    }

    /// <summary>Java/Minecraft style .properties (OptiFine/Iris shaders.properties, lang files).</summary>
    public static ParseOutcome ParseProperties(string text)
    {
        var issues = new List<ParseIssue>();
        var entries = new List<IniEntry>();
        var lines = text.Replace("\r\n", "\n").Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var startLine = i + 1;
            var line = lines[i].TrimStart();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('!'))
            {
                continue;
            }

            while (line.EndsWith('\\') && i + 1 < lines.Length)
            {
                line = line[..^1] + lines[++i].TrimStart();
            }

            var separator = line.IndexOfAny(['=', ':']);
            if (separator < 0)
            {
                issues.Add(new ParseIssue("warning", $"Line has no '=' or ':' separator.", startLine, null));
                continue;
            }

            entries.Add(new IniEntry(line[..separator].Trim(), line[(separator + 1)..].Trim(), "set", startLine));
        }

        var duplicates = entries.GroupBy(e => e.Key).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        foreach (var key in duplicates)
        {
            issues.Add(new ParseIssue("info", $"Key '{key}' is defined more than once; the last value wins.", null, null));
        }

        return new ParseOutcome(true, issues, new { entries = entries.Count, duplicates = duplicates.Count }, entries);
    }

    public static ParseOutcome ParseJson(string text, bool includeData)
    {
        try
        {
            var node = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
                MaxDepth = 256,
            });

            var stats = new JsonStats();
            Walk(node, 1, stats);
            var summary = new
            {
                rootKind = node?.GetValueKind().ToString() ?? "Null",
                topLevelKeys = node is JsonObject obj ? obj.Select(p => p.Key).Take(100).ToList() : null,
                objects = stats.Objects,
                arrays = stats.Arrays,
                values = stats.Values,
                maxDepth = stats.MaxDepth,
            };

            return new ParseOutcome(true, [], summary, includeData ? node : null);
        }
        catch (JsonException ex)
        {
            return new ParseOutcome(false, [new ParseIssue("error", ex.Message, ex.LineNumber + 1, ex.BytePositionInLine + 1)], null, null);
        }
    }

    public static ParseOutcome ParseXml(string text, long maxCharacters)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, // no XXE / billion-laughs
            XmlResolver = null,
            MaxCharactersInDocument = maxCharacters,
            IgnoreComments = true,
        };

        try
        {
            using var reader = XmlReader.Create(new StringReader(text), settings);
            var document = XDocument.Load(reader, LoadOptions.SetLineInfo);
            var root = document.Root!;
            var elements = root.DescendantsAndSelf().ToList();
            var summary = new
            {
                root = root.Name.LocalName,
                ns = root.Name.NamespaceName.Length > 0 ? root.Name.NamespaceName : null,
                elements = elements.Count,
                attributes = elements.Sum(e => e.Attributes().Count()),
                maxDepth = elements.Max(e => e.Ancestors().Count()) + 1,
                topElementNames = elements.GroupBy(e => e.Name.LocalName)
                    .OrderByDescending(g => g.Count()).Take(30)
                    .ToDictionary(g => g.Key, g => g.Count()),
                children = root.Elements().Select(e => e.Name.LocalName).Distinct().Take(50).ToList(),
            };

            return new ParseOutcome(true, [], summary, null);
        }
        catch (XmlException ex)
        {
            return new ParseOutcome(false, [new ParseIssue("error", ex.Message, ex.LineNumber, ex.LinePosition)], null, null);
        }
    }

    private sealed class JsonStats
    {
        public int Objects;
        public int Arrays;
        public int Values;
        public int MaxDepth;
    }

    private static void Walk(JsonNode? node, int depth, JsonStats stats)
    {
        stats.MaxDepth = Math.Max(stats.MaxDepth, depth);
        switch (node)
        {
            case JsonObject obj:
                stats.Objects++;
                foreach (var property in obj)
                {
                    Walk(property.Value, depth + 1, stats);
                }

                break;
            case JsonArray array:
                stats.Arrays++;
                foreach (var item in array)
                {
                    Walk(item, depth + 1, stats);
                }

                break;
            default:
                stats.Values++;
                break;
        }
    }
}
