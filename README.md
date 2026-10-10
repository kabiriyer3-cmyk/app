# Local MCP Server for Windows

A standalone Windows tray application that exposes a **local, permission-bounded** [Model Context Protocol](https://modelcontextprotocol.io) server for AI development tools (Claude Desktop, VS Code / Copilot, Cursor, etc.). Built on the official **MCP C# SDK** (`ModelContextProtocol.AspNetCore` 2.2.0) and .NET 10, shipped as a single self-contained `.exe`.

## Transports

| Mode | How it starts | Network | Auth |
|---|---|---|---|
| **stdio** | Client launches `LocalMcpServer.exe --stdio` | none | process boundary |
| **Streamable HTTP** | Run the exe → tray icon | `127.0.0.1` / `[::1]` only, port 39217 | Bearer token + Host/Origin checks |

## Security model

* **Workspaces are the only thing visible.** Clients address files as `workspace` + relative path. Nothing outside configured roots is reachable.
* **Read-only by default.** Write access is granted per workspace, with a confirmation dialog.
* **Path hardening** (`Security/WorkspaceGuard.cs`): rejects `..`, absolute/UNC/device paths, NTFS alternate data streams (`:`), reserved device names (`CON`, `NUL`, `COM1`…), trailing dot/space tricks, and symlinks/junctions that resolve outside the root. Recursion never follows links.
* **Root restrictions:** no whole drives, no whole user profile, Windows/Program Files only read-only, and the server's own settings/token/install folders can never be shared (a client can't grant itself access).
* **Write policy:** blocked executable/script extensions, size limits, atomic temp-file + rename writes, optional `expectedSha256` optimistic concurrency, deletes disabled by default and routed to the Recycle Bin.
* **HTTP hardening** (`Security/LocalRequestGuard.cs`): loopback peers only, strict `Host` header (DNS-rebinding defence), `Origin` validation, constant-time bearer token comparison, no `Server` header.
* **No process execution.** Tools never spawn processes and never expose environment variables. XML parsing has DTDs disabled (no XXE).
* **Refuses to run elevated** (configurable) and the manifest is `asInvoker`.
* **Audit log** of every call and every denial: `%LOCALAPPDATA%\LocalMcpServer\logs\audit-YYYYMMDD.log`, live in the dashboard.

## Tools

**Core:** `list_workspaces`, `list_directory`, `read_text_file`, `read_binary_file`, `get_file_info`, `search_files`, `write_text_file`, `create_directory`, `copy_file`, `move_path`, `delete_path`, `get_system_info`, `detect_dev_tools`

**Modding & analysis:** `inspect_mod_structure` (tree, stats, ecosystem detection for Unreal PAK/IoStore, Unity/BepInEx, Minecraft resource & shader packs, Bethesda, Source + packaging warnings such as missing `_P` suffix or incomplete `.pak/.utoc/.ucas` trios), `parse_config_file` (UE INI with `+ - . !` operators, JSON with comments, XML, `.properties`), `identify_file_format` (magic bytes), `inspect_unreal_file` (`.pak` footer, `.utoc` header, `.uasset` summary), `compare_directories`, `compute_file_hashes`.

All tools carry MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint=false`).

## Configuration

First run copies `localmcp.defaults.json` to `%APPDATA%\LocalMcpServer\settings.json`. Edit via the dashboard (tray icon → Open dashboard) or by hand:

```json
{
  "workspaces": [
    { "name": "my-mod", "path": "D:\\Modding\\MyMod", "access": "ReadWrite" },
    { "name": "game-paks", "path": "D:\\SteamLibrary\\steamapps\\common\\Ready Or Not\\ReadyOrNot\\Content\\Paks", "access": "ReadOnly" }
  ],
  "enableHttp": true,
  "httpPort": 39217,
  "allowDelete": false
}
```

Use `--config <path>` for a portable settings file.

## Client setup

**Claude Desktop / Cursor (stdio)** — `claude_desktop_config.json`:

```json
{ "mcpServers": { "local-mcp": { "command": "C:\\Tools\\LocalMcpServer.exe", "args": ["--stdio"] } } }
```

**VS Code (HTTP)** — `.vscode/mcp.json` (the dashboard's *Copy HTTP client config* fills in the token):

```json
{
  "inputs": [{ "id": "mcpToken", "type": "promptString", "description": "Local MCP token", "password": true }],
  "servers": {
    "local-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:39217/mcp",
      "headers": { "Authorization": "Bearer ${input:mcpToken}" }
    }
  }
}
```

## Build

```powershell
dotnet test LocalMcpServer.slnx
dotnet publish src/LocalMcpServer/LocalMcpServer.csproj -c Release -r win-x64 -o publish
```

## Release

```bash
git tag v1.0.0
git push origin v1.0.0
```

`.github/workflows/release.yml` then runs tests, publishes self-contained single-file builds for `win-x64` and `win-arm64`, optionally Authenticode-signs them (set `WINDOWS_SIGNING_CERT_BASE64` and `WINDOWS_SIGNING_CERT_PASSWORD` secrets), generates `SHA256SUMS.txt`, attests build provenance (public repos) and publishes a GitHub Release. Tags containing `-` (e.g. `v1.1.0-beta.1`) become pre-releases.

## Project layout

```
.github/workflows/   ci.yml, release.yml
src/LocalMcpServer/
  Program.cs                 entry point (tray vs --stdio)
  Configuration/             ServerOptions, SettingsStore (settings + token)
  Security/                  WorkspaceGuard (path boundary), LocalRequestGuard (HTTP)
  Hosting/                   MCP registration, stdio host, loopback HTTP host
  Tools/                     FileSystemTools, SystemInfoTools, ModdingTools, models
  Modding/                   FormatSniffer, UnrealFormats, ConfigParsers
  Infrastructure/            AuditLog, hashing, error wrapping
  UI/                        Tray context + dashboard (WinForms)
tests/LocalMcpServer.Tests/  boundary + parser tests (xUnit)
```
