package com.flechazo.apisentinel.ai.pipeline;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Endpoint attribution for cluster-hunting verdicts — the test data mirrors
 * the exact shapes real Agent runs produce (see the 2026-08-19
 * api-products-search report: verifyCommands like
 * "GET /api/users/search?name=' OR '1'='1 （URL 编码后）" and titles like
 * "错误回显 SQL 注入（/api/users/search）").
 */
class VulnEndpointAttributorTest {

    @Test
    void parsesMethodAndPathFromVerifyCommand() {
        ConfirmedVuln v = new ConfirmedVuln("SQL注入", "错误回显 SQL 注入（/api/users/search）",
                "e", "name=' OR '1'='1", "resp",
                "GET /api/users/search?name=' OR '1'='1 （URL 编码后）");
        assertEquals("/api/users/search", VulnEndpointAttributor.extractEndpoint(v));
        assertEquals("GET", VulnEndpointAttributor.extractMethod(v.verifyCommand(), "GET"));
    }

    @Test
    void stripsQueryAndHandlesPostBodies() {
        assertEquals("/api/fetch-url",
                VulnEndpointAttributor.extractEndpoint("POST /api/fetch-url {\"url\":\"http://x\"}", null));
        assertEquals("POST",
                VulnEndpointAttributor.extractMethod("POST /api/fetch-url {\"url\":\"http://x\"}", "GET"));
        assertEquals("/api/parse-xml",
                VulnEndpointAttributor.extractEndpoint("POST /api/parse-xml 携带上述 XML body（Content-Type: application/xml）", null));
    }

    @Test
    void fallsBackToTitleParenthesizedPath() {
        ConfirmedVuln v = new ConfirmedVuln("SSTI", "服务端模板注入 SSTI（/api/render）",
                "e", "template=${7*7}", "49", null);
        assertEquals("/api/render", VulnEndpointAttributor.extractEndpoint(v));
        assertEquals("/api/greet",
                VulnEndpointAttributor.extractEndpoint(null, "反射型 XSS(/api/greet)"));
    }

    @Test
    void returnsNullWhenNoEndpointSignal() {
        assertNull(VulnEndpointAttributor.extractEndpoint((String) null, "普通反射注入"));
        assertNull(VulnEndpointAttributor.extractEndpoint("检查响应差异", "布尔盲注"));
        assertNull(VulnEndpointAttributor.extractEndpoint(null, null));
        // Method extraction falls back when verifyCommand is absent.
        assertEquals("GET", VulnEndpointAttributor.extractMethod(null, "GET"));
    }

    @Test
    void crossEndpointDetection() {
        ConfirmedVuln cross = new ConfirmedVuln("XSS", "反射型 XSS（/api/greet）",
                "e", "p", "r", "GET /api/greet?name=<script>");
        ConfirmedVuln own = new ConfirmedVuln("XSS", "反射型 XSS", "e", "p", "r",
                "GET /api/products/search?name=<script>");

        assertTrue(VulnEndpointAttributor.isCrossEndpoint("/api/products/search", cross));
        assertFalse(VulnEndpointAttributor.isCrossEndpoint("/api/products/search", own));
        // Unresolvable endpoint = belongs to the source, never cross.
        assertFalse(VulnEndpointAttributor.isCrossEndpoint("/api/products/search",
                new ConfirmedVuln("XSS", "无端点信息", "e", "p", "r", null)));

        assertTrue(VulnEndpointAttributor.isCrossEndpointLike("/a", "/b"));
        assertFalse(VulnEndpointAttributor.isCrossEndpointLike("/a", "/a"));
        // Path comparison is case-insensitive (Windows-style hosts).
        assertFalse(VulnEndpointAttributor.isCrossEndpointLike("/API/Users", "/api/users"));
        assertFalse(VulnEndpointAttributor.isCrossEndpointLike("/a", null));
    }

    @Test
    void suspectedVulnOverloadUsesSameRules() {
        SuspectedVuln s = new SuspectedVuln("反序列化", "Java 不安全反序列化（/api/import）",
                "r", "POST /api/import <serialized>", "MEDIUM");
        assertEquals("/api/import", VulnEndpointAttributor.extractEndpoint(s));
        assertNull(VulnEndpointAttributor.extractEndpoint(
                new SuspectedVuln("SQL注入", "布尔盲注", "r", null, "LOW")));
    }
}
