package com.flechazo.apisentinel.integration;

import com.flechazo.apisentinel.mcp.McpSecurityScanner;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MCP 扫描集成测试
 *
 * 用本地 {@link HttpServer} 模拟一个暴露的 MCP 端点（200 无认证、返回含 tools 的 JSON），
 * 跑真实 HTTP 往返，验证 {@link McpSecurityScanner#scan} 的端点发现与风险评估。
 *
 * 注意：生产代码为兼容 Burp 精简 JRE 不使用 jdk.httpserver，但测试 JDK 含该模块，
 * 在此仅作测试桩使用。
 *
 * @since 1.1.0
 */
class McpScanIntegrationTest {

    private HttpServer server;

    private HttpServer startServer(String path, int status, String body) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext(path, (HttpExchange ex) -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, bytes.length);
            try (var os = ex.getResponseBody()) {
                os.write(bytes);
            }
        });
        // 兜底：其它路径返回 404（HttpServer 默认即如此，显式上下文避免 hang）
        s.createContext("/", (HttpExchange ex) -> {
            ex.sendResponseHeaders(404, -1);
            ex.close();
        });
        s.start();
        return s;
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    @Test
    @Timeout(30)
    void scan_unauthenticatedMcpWithTools_detectedCritical() throws IOException {
        // 暴露的 MCP 端点：200、无认证、返回 2 个工具
        String body = "{\"server\":\"vuln-mcp\",\"tools\":[{\"name\":\"read_file\"},{\"name\":\"exec\"}]}";
        server = startServer("/mcp", 200, body);

        String target = "http://127.0.0.1:" + server.getAddress().getPort();
        McpSecurityScanner.ScanResult result = new McpSecurityScanner(null).scan(target);

        assertTrue(result.hasEndpoints(), "应发现 /mcp 端点");
        // 注意：HttpServer 的 /mcp 上下文按前缀匹配，/mcp/v1、/mcp/config 也会命中，
        // 故端点数 ≥1 而非精确等于 1。
        assertTrue(result.endpoints().size() >= 1);
        // 至少一个端点判为 CRITICAL（无认证 + 有工具）
        assertTrue(result.criticalCount() >= 1);
        McpSecurityScanner.McpEndpoint ep = result.endpoints().get(0);
        assertEquals(200, ep.statusCode());
        assertFalse(ep.authRequired(), "200 应判定为无认证");
        assertTrue(ep.toolCount() >= 1, "应提取到工具数量");
        assertEquals("CRITICAL", ep.riskLevel(), "无认证 + 有工具 = CRITICAL");
    }

    @Test
    @Timeout(30)
    void scan_authRequiredMcp_notCritical() throws IOException {
        // 401 = 需认证
        server = startServer("/mcp", 401, "{}");

        String target = "http://127.0.0.1:" + server.getAddress().getPort();
        McpSecurityScanner.ScanResult result = new McpSecurityScanner(null).scan(target);

        assertTrue(result.hasEndpoints());
        McpSecurityScanner.McpEndpoint ep = result.endpoints().get(0);
        assertTrue(ep.authRequired(), "401 应判定为需认证");
        // 有认证 → 非 CRITICAL（HIGH：无工具；测注：mock 未设安全头）
        assertNotEquals("CRITICAL", ep.riskLevel());
        assertEquals(0, result.criticalCount());
    }

    @Test
    @Timeout(30)
    void scan_noMcpPath_returnsNoEndpoints() throws IOException {
        // 服务器只有 /health，不含任何 MCP 路径 → 全部 404
        server = startServer("/health", 200, "ok");

        String target = "http://127.0.0.1:" + server.getAddress().getPort();
        McpSecurityScanner.ScanResult result = new McpSecurityScanner(null).scan(target);

        assertFalse(result.hasEndpoints(), "无 MCP 路径响应 200/401/403，不应发现端点");
        assertEquals(0, result.criticalCount());
    }

    @Test
    @Timeout(30)
    void scan_concurrentProbes_produceSortedDeterministicOutput() throws IOException {
        // /mcp 上下文按前缀匹配 /mcp、/mcp/v1、/mcp/config 三个路径 → 多个端点
        String body = "{\"server\":\"x\",\"tools\":[{\"name\":\"a\"}]}";
        server = startServer("/mcp", 200, body);

        String target = "http://127.0.0.1:" + server.getAddress().getPort();
        McpSecurityScanner.ScanResult result = new McpSecurityScanner(null).scan(target);

        // 并发探测完成顺序不确定，但结果按 URL 排序保证确定性
        for (int i = 1; i < result.endpoints().size(); i++) {
            String prev = result.endpoints().get(i - 1).url();
            String cur = result.endpoints().get(i).url();
            assertTrue(prev.compareTo(cur) <= 0,
                    "端点应按 URL 升序排列: " + prev + " 应 <= " + cur);
        }
        // 第一个端点是 /mcp（字典序最小）
        if (result.hasEndpoints()) {
            assertTrue(result.endpoints().get(0).url().endsWith("/mcp"));
        }
    }

    @Test
    @Timeout(30)
    void scan_toJson_containsBaseUrlAndEndpoints() throws IOException {
        String body = "{\"server\":\"x\",\"tools\":[{\"name\":\"a\"}]}";
        server = startServer("/mcp", 200, body);

        String target = "http://127.0.0.1:" + server.getAddress().getPort();
        McpSecurityScanner.ScanResult result = new McpSecurityScanner(null).scan(target);

        com.google.gson.JsonObject json = result.toJson();
        assertEquals(target, json.get("base_url").getAsString());
        assertTrue(json.get("endpoints_found").getAsInt() >= 1);
        assertTrue(json.get("critical_risk").getAsInt() >= 1);
        assertTrue(json.has("endpoints"));
    }
}
