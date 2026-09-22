package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.mcp.McpSecurityScanner;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * scan_mcp_servers — MCP 服务器安全扫描工具
 *
 * 发现和评估暴露的 Model Context Protocol (MCP) 服务器：
 * - 自动探测常见 MCP 端点（/.well-known/mcp, /mcp, /api/mcp 等）
 * - 检测认证缺失（研究发现 100% 的暴露 MCP 服务器无认证）
 * - 枚举可用工具数量
 * - 评估安全风险等级
 *
 * 参考 MCP-Scanner 的研究：扫描到 1,862 个暴露的 MCP 服务器，100% 缺少认证。
 *
 * 零 LLM 成本，纯网络探测。
 *
 * @since 1.2.0
 */
public class ScanMcpServersTool implements AgentTool {

    private final ToolContext ctx;
    private final McpSecurityScanner scanner;

    public ScanMcpServersTool(ToolContext ctx) {
        this.ctx = ctx;
        this.scanner = new McpSecurityScanner(ctx.logger());
    }

    @Override
    public String name() { return "scan_mcp_servers"; }

    @Override
    public boolean isReadOnly() { return true; }

    @Override
    public String description() {
        return "Scan for exposed Model Context Protocol (MCP) servers and assess security risks. "
             + "Probes common MCP endpoints (/.well-known/mcp, /mcp, /api/mcp, etc.), "
             + "checks for missing authentication (research shows 100% of exposed MCP servers lack auth), "
             + "enumerates available tools, and evaluates risk levels. "
             + "Based on MCP-Scanner research (1,862 exposed servers found, all unauthenticated). "
             + "Zero LLM cost — pure network probing.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        props.add("target_url", prop("string",
                "Target base URL to scan (e.g. 'https://example.com' or 'example.com')"));

        props.add("scan_current_host", prop("boolean",
                "If true, scan the current API entry's host (default: false)"));

        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args;
        try {
            args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        } catch (Exception e) {
            return err("Invalid JSON: " + e.getMessage());
        }

        String targetUrl = str(args, "target_url");
        boolean scanCurrentHost = bool(args, "scan_current_host", false);

        // Determine target
        if ((targetUrl == null || targetUrl.isEmpty()) && scanCurrentHost) {
            var entry = ctx.entry();
            if (entry != null && entry.getDomain() != null) {
                targetUrl = "https://" + entry.getDomain();
            }
        }

        if (targetUrl == null || targetUrl.isEmpty()) {
            return err("target_url is required, or set scan_current_host=true");
        }

        if (ctx.logger() != null) {
            ctx.logger().info("[scan_mcp_servers] Scanning %s...", targetUrl);
        }

        // Execute scan
        McpSecurityScanner.ScanResult result = scanner.scan(targetUrl);

        // Build response
        JsonObject out = result.toJson();
        out.addProperty("success", !result.errors().isEmpty() || result.hasEndpoints());

        if (result.hasEndpoints()) {
            int critical = result.criticalCount();
            if (critical > 0) {
                out.addProperty("warning", String.format(
                        "Found %d CRITICAL risk MCP endpoint(s) without authentication!",
                        critical
                ));
                out.addProperty("next_step",
                        "Immediately add authentication to exposed MCP servers. "
                        + "Review exposed tools for sensitive operations. "
                        + "Consider restricting access by IP whitelist.");
            } else {
                out.addProperty("next_step",
                        "MCP endpoints found but appear to have authentication. "
                        + "Verify security headers and tool permissions.");
            }
        } else {
            out.addProperty("message", "No MCP endpoints found on target");
            out.addProperty("next_step", "Target does not appear to expose MCP servers");
        }

        return out.toString();
    }

    private static JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private static String str(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return null;
    }

    private static boolean bool(JsonObject obj, String key, boolean def) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsBoolean();
        }
        return def;
    }

    private static String err(String msg) {
        JsonObject o = new JsonObject();
        o.addProperty("success", false);
        o.addProperty("error", msg);
        return o.toString();
    }
}
