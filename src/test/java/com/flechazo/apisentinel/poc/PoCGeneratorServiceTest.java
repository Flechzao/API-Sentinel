package com.flechazo.apisentinel.poc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PoCGeneratorService 单元测试
 *
 * @since 1.2.0
 */
class PoCGeneratorServiceTest {

    private PoCGeneratorService service;

    @BeforeEach
    void setUp() {
        // PoCGeneratorService 的 generate 方法不使用 logger，可传 null
        service = new PoCGeneratorService(null);
    }

    @Test
    void generate_sqlInjection_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "CRITICAL", "GET /api/users/{id}",
                "GET", "https://example.com/api/users?id=1",
                "1' OR '1'='1", "Response contains all users",
                "SQL injection in id parameter",
                "Use parameterized queries",
                "session=abc123", null, 95
        );

        assertNotNull(poc);
        assertEquals("SQL Injection", poc.vulnType());
        assertEquals("CRITICAL", poc.severity());
        assertTrue(poc.title().contains("SQL Injection"));
        assertTrue(poc.title().contains("/api/users"));
        assertNotNull(poc.curlCommand());
        assertNotNull(poc.pythonScript());
        assertEquals(6, poc.steps().size());
        assertEquals(95, poc.confidence());
    }

    @Test
    void generate_xss_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "XSS", "HIGH", "GET /api/search",
                "GET", "https://example.com/api/search?q=test",
                "<script>alert(1)</script>", "Script reflected in response",
                "Reflected XSS in search parameter",
                "Encode output",
                null, null, 85
        );

        assertNotNull(poc);
        assertEquals("XSS", poc.vulnType());
        assertTrue(poc.title().contains("Cross-Site Scripting"));
        assertNotNull(poc.curlCommand());
    }

    @Test
    void generate_idor_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "BOLA", "HIGH", "GET /api/orders/{id}",
                "GET", "https://example.com/api/orders/123",
                null, "Can access other user's order",
                "IDOR in order endpoint",
                "Implement proper authorization",
                "user_a_cookie=xyz", null, 90
        );

        assertNotNull(poc);
        assertTrue(poc.vulnType().contains("BOLA") || poc.vulnType().contains("IDOR"));
        assertTrue(poc.title().contains("BOLA") || poc.title().contains("IDOR"));
        // IDOR PoC should have two curl commands (user A and user B)
        assertTrue(poc.curlCommand().contains("用户 A") || poc.curlCommand().contains("User A")
                || poc.curlCommand().contains("#"));
    }

    @Test
    void generate_ssrf_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "SSRF", "HIGH", "POST /api/fetch",
                "POST", "https://example.com/api/fetch",
                "http://169.254.169.254/latest/meta-data/",
                "AWS metadata returned",
                "SSRF via URL parameter",
                "Validate and whitelist URLs",
                null, null, 88
        );

        assertNotNull(poc);
        assertEquals("SSRF", poc.vulnType());
        assertTrue(poc.description().contains("169.254.169.254") || poc.description().contains("AWS"));
    }

    @Test
    void generate_pathTraversal_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "Path Traversal", "HIGH", "GET /api/files",
                "GET", "https://example.com/api/files?path=test.txt",
                "../../etc/passwd", "passwd file contents",
                "Path traversal vulnerability",
                "Validate file paths",
                null, null, 92
        );

        assertNotNull(poc);
        assertEquals("Path Traversal", poc.vulnType());
    }

    @Test
    void generate_ssti_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "SSTI", "CRITICAL", "POST /api/render",
                "POST", "https://example.com/api/render",
                "{{7*7}}", "49",
                "Server-side template injection",
                "Use safe template engines",
                null, null, 95
        );

        assertNotNull(poc);
        assertEquals("SSTI", poc.vulnType());
    }

    @Test
    void generate_xxe_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "XXE", "HIGH", "POST /api/xml",
                "POST", "https://example.com/api/xml",
                null, "File contents leaked",
                "XXE vulnerability",
                "Disable external entities",
                null, null, 90
        );

        assertNotNull(poc);
        assertEquals("XXE", poc.vulnType());
        // XXE PoC should include XML payload
        assertTrue(poc.payload().contains("<!DOCTYPE") || poc.payload().contains("<!ENTITY"));
    }

    @Test
    void generate_commandInjection_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "Command Injection", "CRITICAL", "POST /api/ping",
                "POST", "https://example.com/api/ping",
                "; id", "uid=0(root)",
                "Command injection",
                "Sanitize input",
                null, null, 98
        );

        assertNotNull(poc);
        assertEquals("Command Injection", poc.vulnType());
    }

    @Test
    void generate_massAssignment_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "Mass Assignment", "HIGH", "PUT /api/users/{id}",
                "PUT", "https://example.com/api/users/1",
                "{\"isAdmin\":true}", "isAdmin updated",
                "Mass assignment vulnerability",
                "Use allowlist for fields",
                null, null, 85
        );

        assertNotNull(poc);
        assertEquals("Mass Assignment", poc.vulnType());
        assertTrue(poc.payload().contains("isAdmin"));
    }

    @Test
    void generate_authBypass_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "Authentication Bypass", "CRITICAL", "GET /api/admin",
                "GET", "https://example.com/api/admin",
                null, "Access without auth",
                "Auth bypass",
                "Implement proper authentication",
                null, null, 90
        );

        assertNotNull(poc);
        assertTrue(poc.vulnType().contains("Authentication"));
    }

    @Test
    void generate_csrf_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "CSRF", "MEDIUM", "POST /api/transfer",
                "POST", "https://example.com/api/transfer",
                null, "Transfer without CSRF token",
                "CSRF vulnerability",
                "Implement CSRF tokens",
                null, null, 80
        );

        assertNotNull(poc);
        assertEquals("CSRF", poc.vulnType());
        // CSRF PoC should include HTML form
        assertNotNull(poc.pythonScript());
        assertTrue(poc.pythonScript().contains("<form") || poc.pythonScript().contains("csrf"));
    }

    @Test
    void generate_openRedirect_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "Open Redirect", "LOW", "GET /api/redirect",
                "GET", "https://example.com/api/redirect",
                "https://evil.com", "Redirected to evil.com",
                "Open redirect",
                "Validate redirect URLs",
                null, null, 70
        );

        assertNotNull(poc);
        assertEquals("Open Redirect", poc.vulnType());
    }

    @Test
    void generate_nosqlInjection_returnsValidPoC() {
        ProofOfConcept poc = service.generate(
                "NoSQL Injection", "HIGH", "POST /api/login",
                "POST", "https://example.com/api/login",
                "{\"$ne\":\"\"}", "Login bypass",
                "NoSQL injection",
                "Use parameterized queries",
                null, null, 90
        );

        assertNotNull(poc);
        // NoSQL Injection normalizes to SQL Injection in PoC generator
        assertTrue(poc.vulnType().contains("SQL") || poc.vulnType().contains("Injection"));
        assertTrue(poc.payload().contains("$ne"));
    }

    @Test
    void generate_unknownType_returnsGenericPoC() {
        ProofOfConcept poc = service.generate(
                "Custom Vulnerability", "MEDIUM", "GET /api/custom",
                "GET", "https://example.com/api/custom",
                "test_payload", "evidence",
                "Custom vulnerability description",
                "Fix it",
                null, null, 50
        );

        assertNotNull(poc);
        assertEquals("Custom Vulnerability", poc.vulnType());
        assertTrue(poc.title().contains("Custom Vulnerability"));
    }

    @Test
    void generate_nullVulnType_defaultsToUnknown() {
        ProofOfConcept poc = service.generate(
                null, "MEDIUM", "GET /api/test",
                "GET", "https://example.com/api/test",
                null, null, null, null, null, null, 50
        );

        assertNotNull(poc);
        assertEquals("Unknown", poc.vulnType());
    }

    @Test
    void generate_emptyVulnType_defaultsToUnknown() {
        ProofOfConcept poc = service.generate(
                "", "MEDIUM", "GET /api/test",
                "GET", "https://example.com/api/test",
                null, null, null, null, null, null, 50
        );

        assertNotNull(poc);
        assertEquals("Unknown", poc.vulnType());
    }

    @Test
    void generate_withCookies_includesInCurl() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "HIGH", "GET /api/users",
                "GET", "https://example.com/api/users?id=1",
                "1' OR '1'='1", "evidence",
                "desc", "fix",
                "session=abc123; user=test", null, 90
        );

        assertTrue(poc.curlCommand().contains("Cookie:"));
        assertTrue(poc.curlCommand().contains("session=abc123"));
    }

    @Test
    void generate_withHeaders_includesInCurl() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "HIGH", "GET /api/users",
                "GET", "https://example.com/api/users?id=1",
                "1' OR '1'='1", "evidence",
                "desc", "fix",
                null, "X-Custom-Header: value\nAuthorization: Bearer token", 90
        );

        assertTrue(poc.curlCommand().contains("X-Custom-Header"));
        assertTrue(poc.curlCommand().contains("Authorization"));
    }

    @Test
    void generate_pythonScript_hasShebang() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "HIGH", "GET /api/users",
                "GET", "https://example.com/api/users?id=1",
                "payload", "evidence",
                "desc", "fix",
                null, null, 90
        );

        assertTrue(poc.pythonScript().startsWith("#!/usr/bin/env python3"));
    }

    @Test
    void generate_pythonScript_importsRequests() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "HIGH", "GET /api/users",
                "GET", "https://example.com/api/users?id=1",
                "payload", "evidence",
                "desc", "fix",
                null, null, 90
        );

        assertTrue(poc.pythonScript().contains("import requests"));
    }

    @Test
    void generate_postMethod_usesPostInCurl() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "HIGH", "POST /api/login",
                "POST", "https://example.com/api/login",
                "{\"user\":\"admin'--\"}", "evidence",
                "desc", "fix",
                null, null, 90
        );

        assertTrue(poc.curlCommand().contains("curl -X POST"));
    }

    @Test
    void generate_putMethod_usesPutInPython() {
        ProofOfConcept poc = service.generate(
                "Mass Assignment", "HIGH", "PUT /api/users/1",
                "PUT", "https://example.com/api/users/1",
                "{\"isAdmin\":true}", "evidence",
                "desc", "fix",
                null, null, 90
        );

        assertTrue(poc.pythonScript().contains("requests.put"));
    }

    @Test
    void generate_deleteMethod_usesDeleteInPython() {
        ProofOfConcept poc = service.generate(
                "BOLA", "HIGH", "DELETE /api/users/1",
                "DELETE", "https://example.com/api/users/1",
                null, "evidence",
                "desc", "fix",
                null, null, 90
        );

        assertTrue(poc.pythonScript().contains("requests.delete"));
    }

    @Test
    void normalizeType_handlesVariations() {
        // Test various input formats that should normalize to the same type
        ProofOfConcept poc1 = service.generate("SQL Injection", "HIGH", "/api", "GET", "http://x", null, null, null, null, null, null, 50);
        ProofOfConcept poc2 = service.generate("sql-injection", "HIGH", "/api", "GET", "http://x", null, null, null, null, null, null, 50);
        ProofOfConcept poc3 = service.generate("SQL_INJECTION", "HIGH", "/api", "GET", "http://x", null, null, null, null, null, null, 50);

        assertEquals("SQL Injection", poc1.vulnType());
        assertEquals("SQL Injection", poc2.vulnType());
        assertEquals("SQL Injection", poc3.vulnType());
    }

    @Test
    void generate_allStepsPresent() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "HIGH", "GET /api/users",
                "GET", "https://example.com/api/users?id=1",
                "payload", "evidence",
                "desc", "fix",
                null, null, 90
        );

        assertNotNull(poc.steps());
        assertFalse(poc.steps().isEmpty());
        // All PoC types should have exactly 6 steps
        assertEquals(6, poc.steps().size());
    }

    @Test
    void generate_curlCommandEscapesSingleQuotes() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "HIGH", "POST /api/login",
                "POST", "https://example.com/api/login",
                "password=' OR '1'='1", "evidence",
                "desc", "fix",
                null, null, 90
        );

        // Single quotes in payload should be escaped in curl command
        assertTrue(poc.curlCommand().contains("'\\''") || poc.curlCommand().contains("payload:"));
    }

    @Test
    void generate_impactIsDescriptive() {
        ProofOfConcept poc = service.generate(
                "SQL Injection", "CRITICAL", "GET /api/users",
                "GET", "https://example.com/api/users?id=1",
                "payload", "evidence",
                "desc", "fix",
                null, null, 90
        );

        assertNotNull(poc.impact());
        assertTrue(poc.impact().length() > 20, "Impact should be descriptive");
    }

    @Test
    void generate_idorWithIdInUrl_extractsId() {
        ProofOfConcept poc = service.generate(
                "IDOR", "HIGH", "GET /api/orders/12345",
                "GET", "https://example.com/api/orders/12345",
                null, "evidence",
                "desc", "fix",
                null, null, 90
        );

        // The curl command should reference the victim's resource ID
        assertTrue(poc.curlCommand().contains("victim") ||
                poc.curlCommand().contains("12345") ||
                poc.curlCommand().contains("{{"));
    }

    @Test
    void generate_idorWithUuidInUrl_handlesUuid() {
        ProofOfConcept poc = service.generate(
                "BOLA", "HIGH", "GET /api/users/550e8400-e29b-41d4-a716-446655440000",
                "GET", "https://example.com/api/users/550e8400-e29b-41d4-a716-446655440000",
                null, "evidence",
                "desc", "fix",
                null, null, 90
        );

        assertNotNull(poc);
        assertNotNull(poc.curlCommand());
    }
}
