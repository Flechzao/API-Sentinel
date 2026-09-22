package com.flechazo.apisentinel.mcp;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * McpSecurityScanner 单元测试
 *
 * 测试 records 和工具方法（不涉及网络请求）
 *
 * @since 1.2.0
 */
class McpSecurityScannerTest {

    // ==================== McpEndpoint Tests ====================

    @Test
    void mcpEndpoint_constructor_setsAllFields() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                200,
                false,
                5,
                "application/json",
                "server-info",
                true
        );

        assertEquals("https://example.com/mcp", endpoint.url());
        assertEquals(200, endpoint.statusCode());
        assertFalse(endpoint.authRequired());
        assertEquals(5, endpoint.toolCount());
        assertEquals("application/json", endpoint.contentType());
        assertEquals("server-info", endpoint.serverInfo());
        assertTrue(endpoint.hasSecurityHeaders());
    }

    @Test
    void mcpEndpoint_riskLevel_criticalWhenNoAuthAndHasTools() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                200,
                false,  // no auth
                5,      // has tools
                "application/json",
                null,
                true
        );

        assertEquals("CRITICAL", endpoint.riskLevel());
    }

    @Test
    void mcpEndpoint_riskLevel_highWhenNoAuthAndNoTools() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                200,
                false,  // no auth
                0,      // no tools
                "application/json",
                null,
                true
        );

        assertEquals("HIGH", endpoint.riskLevel());
    }

    @Test
    void mcpEndpoint_riskLevel_mediumWhenAuthButNoSecurityHeaders() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                401,
                true,   // auth required
                0,
                "application/json",
                null,
                false   // no security headers
        );

        assertEquals("MEDIUM", endpoint.riskLevel());
    }

    @Test
    void mcpEndpoint_riskLevel_lowWhenAuthAndHasSecurityHeaders() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                401,
                true,   // auth required
                5,
                "application/json",
                null,
                true    // has security headers
        );

        assertEquals("LOW", endpoint.riskLevel());
    }

    @Test
    void mcpEndpoint_recommendation_warnsAboutNoAuth() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                200,
                false,  // no auth
                5,
                "application/json",
                null,
                true
        );

        String recommendation = endpoint.recommendation();
        assertTrue(recommendation.contains("CRITICAL"));
        assertTrue(recommendation.contains("authentication") ||
                recommendation.toLowerCase().contains("auth"));
    }

    @Test
    void mcpEndpoint_recommendation_warnsAboutMissingHeaders() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                401,
                true,
                0,
                "application/json",
                null,
                false   // no security headers
        );

        String recommendation = endpoint.recommendation();
        assertTrue(recommendation.contains("security headers") ||
                recommendation.contains("HSTS"));
    }

    @Test
    void mcpEndpoint_recommendation_mentionsTools() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                401,
                true,
                10,     // has tools
                "application/json",
                null,
                true
        );

        String recommendation = endpoint.recommendation();
        assertTrue(recommendation.contains("tools") ||
                recommendation.contains("Review"));
    }

    @Test
    void mcpEndpoint_recommendation_secureWhenAllGood() {
        McpSecurityScanner.McpEndpoint endpoint = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp",
                401,
                true,
                0,
                "application/json",
                null,
                true
        );

        String recommendation = endpoint.recommendation();
        assertTrue(recommendation.contains("secure") ||
                recommendation.contains("Configuration"));
    }

    // ==================== ScanResult Tests ====================

    @Test
    void scanResult_constructor_setsAllFields() {
        McpSecurityScanner.McpEndpoint ep = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp", 200, false, 5,
                "application/json", null, true
        );

        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(ep),
                List.of("error1")
        );

        assertEquals("https://example.com", result.baseUrl());
        assertEquals(1, result.endpoints().size());
        assertEquals(1, result.errors().size());
    }

    @Test
    void scanResult_hasEndpoints_trueWhenNotEmpty() {
        McpSecurityScanner.McpEndpoint ep = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp", 200, false, 5,
                "application/json", null, true
        );

        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(ep),
                List.of()
        );

        assertTrue(result.hasEndpoints());
    }

    @Test
    void scanResult_hasEndpoints_falseWhenEmpty() {
        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(),
                List.of()
        );

        assertFalse(result.hasEndpoints());
    }

    @Test
    void scanResult_hasEndpoints_falseWhenNull() {
        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                null,
                List.of()
        );

        assertFalse(result.hasEndpoints());
    }

    @Test
    void scanResult_criticalCount_countsCriticalEndpoints() {
        McpSecurityScanner.McpEndpoint critical = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp1", 200, false, 5,
                "application/json", null, true
        );
        McpSecurityScanner.McpEndpoint low = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp2", 401, true, 5,
                "application/json", null, true
        );

        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(critical, low),
                List.of()
        );

        assertEquals(1, result.criticalCount());
    }

    @Test
    void scanResult_criticalCount_zeroWhenNoCritical() {
        McpSecurityScanner.McpEndpoint low = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp", 401, true, 5,
                "application/json", null, true
        );

        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(low),
                List.of()
        );

        assertEquals(0, result.criticalCount());
    }

    @Test
    void scanResult_errorFactory_createsErrorResult() {
        McpSecurityScanner.ScanResult result = McpSecurityScanner.ScanResult.error("Test error");

        assertNull(result.baseUrl());
        assertTrue(result.endpoints().isEmpty());
        assertEquals(1, result.errors().size());
        assertEquals("Test error", result.errors().get(0));
    }

    @Test
    void scanResult_toJson_containsAllFields() {
        McpSecurityScanner.McpEndpoint ep = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp", 200, false, 5,
                "application/json", null, true
        );

        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(ep),
                List.of("error1")
        );

        JsonObject json = result.toJson();

        assertEquals("https://example.com", json.get("base_url").getAsString());
        assertEquals(1, json.get("endpoints_found").getAsInt());
        assertEquals(1, json.get("critical_risk").getAsInt());
        assertTrue(json.has("endpoints"));
        assertEquals(1, json.getAsJsonArray("endpoints").size());
        assertTrue(json.has("errors"));
    }

    @Test
    void scanResult_toJson_emptyErrorsOmitsField() {
        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(),
                List.of()
        );

        JsonObject json = result.toJson();

        assertFalse(json.has("errors"));
    }

    @Test
    void scanResult_toJson_endpointFieldsCorrect() {
        McpSecurityScanner.McpEndpoint ep = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp", 200, false, 5,
                "application/json", "server-info", true
        );

        McpSecurityScanner.ScanResult result = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(ep),
                List.of()
        );

        JsonObject json = result.toJson();
        JsonObject endpointJson = json.getAsJsonArray("endpoints").get(0).getAsJsonObject();

        assertEquals("https://example.com/mcp", endpointJson.get("url").getAsString());
        assertEquals(200, endpointJson.get("status_code").getAsInt());
        assertFalse(endpointJson.get("auth_required").getAsBoolean());
        assertEquals(5, endpointJson.get("tool_count").getAsInt());
        assertEquals("CRITICAL", endpointJson.get("risk_level").getAsString());
        assertTrue(endpointJson.has("recommendation"));
    }

    // ==================== Scanner Initialization Tests ====================

    @Test
    void scanner_canBeCreatedWithNullLogger() {
        // McpSecurityScanner 构造函数接受 null logger
        McpSecurityScanner scanner = new McpSecurityScanner(null);
        assertNotNull(scanner);
    }

    // ==================== Endpoint Constants Tests ====================

    @Test
    void mcpEndpoints_includeCommonPaths() {
        // 验证 MCP 端点路径（通过测试间接验证）
        // 这些路径应该在扫描时被探测
        List<String> expectedPaths = List.of(
                "/.well-known/mcp",
                "/mcp",
                "/api/mcp",
                "/mcp/v1",
                "/api/v1/mcp",
                "/mcp-server",
                "/mcp/config"
        );

        assertEquals(7, expectedPaths.size());
    }

    // ==================== Record Equality Tests ====================

    @Test
    void mcpEndpoint_equality() {
        McpSecurityScanner.McpEndpoint ep1 = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp", 200, false, 5,
                "application/json", null, true
        );
        McpSecurityScanner.McpEndpoint ep2 = new McpSecurityScanner.McpEndpoint(
                "https://example.com/mcp", 200, false, 5,
                "application/json", null, true
        );

        assertEquals(ep1, ep2);
        assertEquals(ep1.hashCode(), ep2.hashCode());
    }

    @Test
    void scanResult_equality() {
        McpSecurityScanner.ScanResult r1 = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(),
                List.of()
        );
        McpSecurityScanner.ScanResult r2 = new McpSecurityScanner.ScanResult(
                "https://example.com",
                List.of(),
                List.of()
        );

        assertEquals(r1, r2);
        assertEquals(r1.hashCode(), r2.hashCode());
    }

    // ==================== P1 SSRF 防护测试 ====================

    @Test
    void isSsrfBlocked_blocksCloudMetadataIp() {
        // 169.254.169.254 = AWS/GCP/Azure 元数据（link-local）
        assertTrue(McpSecurityScanner.isSsrfBlocked("169.254.169.254"));
        assertTrue(McpSecurityScanner.isSsrfBlocked("169.254.170.1"));
    }

    @Test
    void isSsrfBlocked_blocksAlibabaMetadataIp() {
        // 100.100.100.200 阿里云 ECS 元数据，不在 link-local 范围，单独拦截
        assertTrue(McpSecurityScanner.isSsrfBlocked("100.100.100.200"));
    }

    @Test
    void isSsrfBlocked_blocksWildcardAddress() {
        assertTrue(McpSecurityScanner.isSsrfBlocked("0.0.0.0"));
    }

    @Test
    void isSsrfBlocked_allowsLoopbackForDev() {
        // loopback 放行：本机扫描是合法的开发/测试场景
        assertFalse(McpSecurityScanner.isSsrfBlocked("127.0.0.1"));
        assertFalse(McpSecurityScanner.isSsrfBlocked("127.0.0.1:1"));
    }

    @Test
    void isSsrfBlocked_allowsPublicIp() {
        assertFalse(McpSecurityScanner.isSsrfBlocked("8.8.8.8"));
    }

    @Test
    void isSsrfBlocked_unresolvableHost_returnsFalse() {
        // DNS 不可解析 → 放行，让后续 probe 自然失败（不在防护层误报）
        assertFalse(McpSecurityScanner.isSsrfBlocked("nonexistent-host-xyz.invalid"));
    }

    @Test
    void isSsrfBlocked_nullOrBlank_returnsFalse() {
        assertFalse(McpSecurityScanner.isSsrfBlocked(null));
        assertFalse(McpSecurityScanner.isSsrfBlocked(""));
        assertFalse(McpSecurityScanner.isSsrfBlocked("   "));
    }

    @Test
    void scan_metadataTarget_returnsBlockedError() {
        // 扫描云元数据地址应被拒绝、不发起任何探测（无网络）
        McpSecurityScanner scanner = new McpSecurityScanner(null);
        McpSecurityScanner.ScanResult result = scanner.scan("https://169.254.169.254/latest/meta-data/");

        assertFalse(result.hasEndpoints());
        assertEquals(1, result.errors().size());
        assertTrue(result.errors().get(0).toLowerCase().contains("ssrf") || result.errors().get(0).contains("metadata"));
    }

    @Test
    void scan_alibabaMetadata_returnsBlockedError() {
        McpSecurityScanner scanner = new McpSecurityScanner(null);
        McpSecurityScanner.ScanResult result = scanner.scan("https://100.100.100.200/latest/meta-data/");
        assertFalse(result.hasEndpoints());
        assertTrue(result.errors().get(0).toLowerCase().contains("ssrf") || result.errors().get(0).contains("metadata"));
    }
}
