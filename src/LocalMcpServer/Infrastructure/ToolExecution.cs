using System.Security;
using ModelContextProtocol;

namespace LocalMcpServer.Infrastructure;

/// <summary>
/// Wraps tool bodies so that filesystem errors reach the client as readable MCP tool errors
/// (instead of a generic failure) and every failure lands in the audit log.
/// </summary>
internal static class ToolExecution
{
    public static T Run<T>(AuditLog audit, string tool, Func<T> body)
    {
        try
        {
            return body();
        }
        catch (McpException ex)
        {
            audit.Write(tool, ex.Message, denied: true);
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException
                                       or ArgumentException or NotSupportedException or SecurityException
                                       or System.Text.Json.JsonException or System.Xml.XmlException)
        {
            audit.Write(tool, ex.Message, denied: true);
            throw new McpException($"{tool} failed: {ex.Message}", ex);
        }
    }
}
