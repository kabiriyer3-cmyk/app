using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LocalMcpServer.Configuration;

/// <summary>
/// Persists settings and the HTTP access token under the current user's profile.
/// These locations are deliberately rejected as workspace roots so an AI client can never rewrite its own permissions.
/// </summary>
public static class SettingsStore
{
    public static string AppDataDirectory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "LocalMcpServer");

    public static string LocalDataDirectory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LocalMcpServer");

    public static string LogDirectory => Path.Combine(LocalDataDirectory, "logs");

    public static string DefaultSettingsPath => Path.Combine(AppDataDirectory, "settings.json");

    public static string TokenPath => Path.Combine(AppDataDirectory, "access-token.txt");

    public static string SeedPath => Path.Combine(AppContext.BaseDirectory, "localmcp.defaults.json");

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static ServerOptions Load(string? overridePath = null)
    {
        var path = overridePath ?? DefaultSettingsPath;

        if (!File.Exists(path))
        {
            if (overridePath is not null)
            {
                throw new FileNotFoundException($"Configuration file not found: {overridePath}");
            }

            if (!File.Exists(SeedPath))
            {
                return new ServerOptions();
            }

            Directory.CreateDirectory(AppDataDirectory);
            File.Copy(SeedPath, path, overwrite: false);
        }

        var text = File.ReadAllText(path);
        return JsonSerializer.Deserialize<ServerOptions>(text, Json) ?? new ServerOptions();
    }

    public static void Save(ServerOptions options, string? overridePath = null)
    {
        var path = overridePath ?? DefaultSettingsPath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(options, Json));
        File.Move(temp, path, overwrite: true);
    }

    public static ServerOptions Clone(ServerOptions options) =>
        JsonSerializer.Deserialize<ServerOptions>(JsonSerializer.Serialize(options, Json), Json)!;

    public static string GetOrCreateAccessToken()
    {
        Directory.CreateDirectory(AppDataDirectory);
        if (File.Exists(TokenPath))
        {
            var existing = File.ReadAllText(TokenPath).Trim();
            if (existing.Length >= 32)
            {
                return existing;
            }
        }

        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        File.WriteAllText(TokenPath, token);
        return token;
    }

    public static string RotateAccessToken()
    {
        if (File.Exists(TokenPath))
        {
            File.Delete(TokenPath);
        }

        return GetOrCreateAccessToken();
    }
}
