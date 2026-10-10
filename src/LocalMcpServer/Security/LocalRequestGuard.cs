using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using LocalMcpServer.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace LocalMcpServer.Security;

public sealed record HttpSecurityContext(string AccessToken, int Port);

/// <summary>
/// Hardening for the HTTP transport, following the MCP Streamable HTTP security guidance:
/// loopback-only peers, strict Host header (DNS-rebinding defence), Origin validation and a bearer token.
/// </summary>
public sealed class LocalRequestGuard(RequestDelegate next, HttpSecurityContext security, AuditLog audit)
{
    private static readonly HashSet<string> LoopbackHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "127.0.0.1", "localhost", "[::1]", "::1",
    };

    private readonly byte[] _expectedToken = Encoding.UTF8.GetBytes(security.AccessToken);

    public async Task InvokeAsync(HttpContext context)
    {
        var remote = context.Connection.RemoteIpAddress;
        if (remote is null || !IPAddress.IsLoopback(remote))
        {
            await RejectAsync(context, StatusCodes.Status403Forbidden, $"Non-loopback client {remote} rejected.");
            return;
        }

        if (!IsAllowedHost(context.Request.Host))
        {
            await RejectAsync(context, StatusCodes.Status403Forbidden, $"Invalid Host header '{context.Request.Host}'.");
            return;
        }

        var origin = context.Request.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(origin) && !IsAllowedOrigin(origin))
        {
            await RejectAsync(context, StatusCodes.Status403Forbidden, $"Cross-origin request from '{origin}' rejected.");
            return;
        }

        var isHealthCheck = context.Request.Path.StartsWithSegments("/healthz");
        if (!isHealthCheck && !IsAuthorized(context.Request.Headers.Authorization.ToString()))
        {
            context.Response.Headers.WWWAuthenticate = "Bearer realm=\"local-mcp-server\"";
            await RejectAsync(context, StatusCodes.Status401Unauthorized, $"Missing or invalid bearer token ({DescribeAuthorization(context.Request.Headers.Authorization.ToString())}).");
            return;
        }

        var started = Stopwatch.GetTimestamp();
        try
        {
            await next(context);
        }
        finally
        {
            // One line per authorized request: makes client/transport problems visible in the audit log.
            var status = context.Response.StatusCode;
            var protocol = context.Request.Headers["MCP-Protocol-Version"].ToString();
            var session = context.Response.Headers["Mcp-Session-Id"].ToString();
            var agent = context.Request.Headers.UserAgent.ToString();
            if (agent.Length > 60)
            {
                agent = agent[..60];
            }

            audit.Write("http",
                $"{context.Request.Method} {context.Request.Path} -> {status} ({Stopwatch.GetElapsedTime(started).TotalMilliseconds:0} ms"
                + (protocol.Length > 0 ? $", protocol {protocol}" : "")
                + (session.Length > 0 ? ", session issued" : "")
                + (agent.Length > 0 ? $", {agent}" : "")
                + ")",
                denied: status >= 400);
        }
    }

    private bool IsAllowedHost(HostString host) =>
        host.HasValue
        && LoopbackHosts.Contains(host.Host)
        && (host.Port is null || host.Port == security.Port);

    private static bool IsAllowedOrigin(string origin) =>
        Uri.TryCreate(origin, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
        && uri.IsLoopback;

    private bool IsAuthorized(string header)
    {
        const string prefix = "Bearer ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var presented = Encoding.UTF8.GetBytes(header[prefix.Length..].Trim());
        return CryptographicOperations.FixedTimeEquals(presented, _expectedToken);
    }

    // Never logs the secret itself, only enough to tell a missing header from a wrong token or wrong scheme.
    private static string DescribeAuthorization(string header)
    {
        if (string.IsNullOrWhiteSpace(header))
        {
            return "no Authorization header";
        }

        var space = header.IndexOf(' ');
        var scheme = space > 0 ? header[..space] : header;
        return scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase)
            ? "Bearer token does not match"
            : $"unexpected scheme '{(scheme.Length > 16 ? scheme[..16] : scheme)}', expected 'Bearer <token>'";
    }

    private async Task RejectAsync(HttpContext context, int status, string reason)
    {
        audit.Write("http", $"{context.Request.Method} {context.Request.Path}: {reason}", denied: true);
        context.Response.StatusCode = status;
        await context.Response.WriteAsJsonAsync(new { error = reason });
    }
}
