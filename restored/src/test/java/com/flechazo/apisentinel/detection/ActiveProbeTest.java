package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the pure (network-free) parts of ActiveProbeExecutor —
 * probe classifiers, trigger conditions and the JWT forger. Probe logic
 * distilled from bughunter's scanners (MIT) — see docs/THIRD-PARTY.md.
 */
class ActiveProbeTest {

    private static String resp(String headers, String body) {
        return "HTTP/1.1 200 OK\r\n" + headers + "\r\n" + body;
    }

    // ===== CORS classification (exact reflection semantics) =====

    @Test
    void cors_exactReflectionWithCredentials_high() {
        String r = resp("Access-Control-Allow-Origin: https://evil.example\r\n"
                + "Access-Control-Allow-Credentials: true", "{}");
        assertEquals("HIGH", ActiveProbeExecutor.classifyCors("https://evil.example", r));
    }

    @Test
    void cors_exactReflectionWithoutCredentials_medium() {
        String r = resp("Access-Control-Allow-Origin: https://evil.example", "{}");
        assertEquals("MEDIUM", ActiveProbeExecutor.classifyCors("https://evil.example", r));
    }

    @Test
    void cors_nullOriginReflectedWithCredentials_high() {
        String r = resp("Access-Control-Allow-Origin: null\r\n"
                + "Access-Control-Allow-Credentials: true", "{}");
        assertEquals("HIGH", ActiveProbeExecutor.classifyCors("null", r));
    }

    @Test
    void cors_noReflection_none() {
        String r = resp("Access-Control-Allow-Origin: https://other.example", "{}");
        assertEquals("NONE", ActiveProbeExecutor.classifyCors("https://evil.example", r));
    }

    @Test
    void cors_wildcardAlone_none() {
        // Wildcard without credentials is informational (SafetyRules parity).
        String r = resp("Access-Control-Allow-Origin: *", "{}");
        assertEquals("NONE", ActiveProbeExecutor.classifyCors("https://evil.example", r));
    }

    @Test
    void cors_wildcardWithCredentials_mediumOnly() {
        // Invalid per spec (browser ignores it) — never a confirmed finding.
        String r = resp("Access-Control-Allow-Origin: *\r\n"
                + "Access-Control-Allow-Credentials: true", "{}");
        assertEquals("MEDIUM", ActiveProbeExecutor.classifyCors("https://evil.example", r));
    }

    @Test
    void cors_noAcaoHeader_none() {
        assertEquals("NONE", ActiveProbeExecutor.classifyCors("https://evil.example", resp("", "{}")));
    }

    @Test
    void cors_reflectionCaseInsensitive() {
        String r = resp("access-control-allow-origin: HTTPS://EVIL.EXAMPLE", "{}");
        assertEquals("MEDIUM", ActiveProbeExecutor.classifyCors("https://evil.example", r));
    }

    // ===== CORS trigger =====

    @Test
    void corsTrigger_acaoPresent_true() {
        assertTrue(ActiveProbeExecutor.shouldProbeCors(resp("Access-Control-Allow-Origin: *", "{}")));
    }

    @Test
    void corsTrigger_cookieJsonApi_true() {
        assertTrue(ActiveProbeExecutor.shouldProbeCors(
                resp("Set-Cookie: sid=abc\r\nContent-Type: application/json", "{}")));
    }

    @Test
    void corsTrigger_plainHtml_false() {
        assertFalse(ActiveProbeExecutor.shouldProbeCors(
                resp("Content-Type: text/html", "<html></html>")));
    }

    // ===== CRLF canary =====

    @Test
    void crlf_canaryInSetCookie_detected() {
        String r = resp("Set-Cookie: crlftest=1; Path=/", "");
        assertTrue(ActiveProbeExecutor.detectCrlfCanary(r));
    }

    @Test
    void crlf_canaryWithOtherCookies_detected() {
        String r = resp("Set-Cookie: sid=abc\r\nSet-Cookie: crlftest=1", "");
        assertTrue(ActiveProbeExecutor.detectCrlfCanary(r));
    }

    @Test
    void crlf_canaryOnlyInBody_notDetected() {
        String r = resp("Content-Type: text/html", "crlftest=1");
        assertFalse(ActiveProbeExecutor.detectCrlfCanary(r));
    }

    @Test
    void crlf_noCanary_notDetected() {
        assertFalse(ActiveProbeExecutor.detectCrlfCanary(resp("Set-Cookie: sid=abc", "")));
        assertFalse(ActiveProbeExecutor.detectCrlfCanary(null));
    }

    // ===== NoSQL differential classification =====

    @Test
    void nosql_baselineRejectedVariantPassed_bypass() {
        assertEquals("BYPASS", ActiveProbeExecutor.classifyNosql(401, 120, 200, 800));
        assertEquals("BYPASS", ActiveProbeExecutor.classifyNosql(403, 120, 302, 0));
        assertEquals("BYPASS", ActiveProbeExecutor.classifyNosql(400, 120, 200, 500));
    }

    @Test
    void nosql_sameStatusLargeBodyDelta_suspicious() {
        // delta 400 > max(64, 200/4=50)
        assertEquals("SUSPICIOUS", ActiveProbeExecutor.classifyNosql(200, 200, 200, 600));
    }

    @Test
    void nosql_sameStatusSmallDelta_none() {
        // delta 30 < max(64, 2000/4=500)
        assertEquals("NONE", ActiveProbeExecutor.classifyNosql(200, 2000, 200, 2030));
    }

    @Test
    void nosql_baselineAccepted_none() {
        // Baseline already 200 — operator variants prove nothing.
        assertEquals("NONE", ActiveProbeExecutor.classifyNosql(200, 100, 200, 100));
    }

    @Test
    void nosql_timingConfirmation() {
        assertTrue(ActiveProbeExecutor.confirmNosqlTiming(2500, 3000));   // >= 70%
        assertTrue(ActiveProbeExecutor.confirmNosqlTiming(2100, 3000));   // boundary
        assertFalse(ActiveProbeExecutor.confirmNosqlTiming(1500, 3000));
    }

    // ===== NoSQL trigger =====

    @Test
    void nosqlTrigger_jsonAuthBody_true() {
        String raw = "POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
                + "{\"username\":\"a\",\"password\":\"b\"}";
        assertTrue(ActiveProbeExecutor.isJsonAuthRequest(raw));
    }

    @Test
    void nosqlTrigger_jsonWithoutAuthKeys_false() {
        String raw = "POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
                + "{\"query\":\"x\",\"page\":1}";
        assertFalse(ActiveProbeExecutor.isJsonAuthRequest(raw));
    }

    @Test
    void nosqlTrigger_nonJson_false() {
        String raw = "POST /api/login HTTP/1.1\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&pass=b";
        assertFalse(ActiveProbeExecutor.isJsonAuthRequest(raw));
    }

    @Test
    void nosqlTrigger_malformedJson_false() {
        String raw = "POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{broken";
        assertFalse(ActiveProbeExecutor.isJsonAuthRequest(raw));
    }

    // ===== JWT forgery =====

    @Test
    void jwtForge_algNoneStructure() {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.sig123";
        String forged = ActiveProbeExecutor.forgeAlgNoneToken(jwt, "none");
        assertNotNull(forged);
        String[] parts = forged.split("\\.", -1);
        assertEquals(3, parts.length);
        assertEquals("", parts[2], "signature must be empty");
        assertEquals("eyJzdWIiOiIxMjM0In0", parts[1], "payload must be preserved");
        String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]),
                java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(header.contains("\"alg\":\"none\""), header);
    }

    @Test
    void jwtForge_caseVariant() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.s";
        String forged = ActiveProbeExecutor.forgeAlgNoneToken(jwt, "None");
        String header = new String(java.util.Base64.getUrlDecoder().decode(forged.split("\\.")[0]),
                java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(header.contains("\"alg\":\"None\""), header);
    }

    @Test
    void jwtForge_malformed_null() {
        assertNull(ActiveProbeExecutor.forgeAlgNoneToken("not-a-jwt", "none"));
        assertNull(ActiveProbeExecutor.forgeAlgNoneToken(null, "none"));
    }

    @Test
    void jwtFind_inAuthorizationHeader() {
        String raw = "GET /api HTTP/1.1\r\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\r\n\r\n";
        assertEquals("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
                ActiveProbeExecutor.findJwtInRequest(raw));
    }

    @Test
    void jwtFind_noneAbsent() {
        assertNull(ActiveProbeExecutor.findJwtInRequest("GET /api HTTP/1.1\r\nHost: x\r\n\r\n"));
        assertNull(ActiveProbeExecutor.findJwtInRequest(null));
    }
}
