package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtSecurityDetectorTest {

    private static String b64url(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String jwt(String headerJson, String payloadJson, String sig) {
        return b64url(headerJson) + "." + b64url(payloadJson) + "." + (sig == null ? "" : sig);
    }

    private static boolean hasFinding(List<HeuristicDetector.HeuristicFinding> fs, String titlePart) {
        return fs.stream().anyMatch(f -> f.title().contains(titlePart));
    }

    // 1.2 — jku header injection detected
    @Test
    void jkuHeader_detected() {
        String token = jwt("{\"alg\":\"HS256\",\"jku\":\"https://evil.com/keys\"}",
                "{\"sub\":\"user\"}", "sig");
        var fs = JwtSecurityDetector.detectJwtIssues("HTTP/1.1 200\r\n\r\n" + token);
        assertTrue(hasFinding(fs, "jku"));
    }

    // 1.2 — embedded jwk detected
    @Test
    void embeddedJwk_detected() {
        String token = jwt("{\"alg\":\"RS256\",\"jwk\":{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}}",
                "{\"sub\":\"user\"}", "sig");
        var fs = JwtSecurityDetector.detectJwtIssues(token);
        assertTrue(hasFinding(fs, "jwk"));
    }

    // 1.2 — kid with path traversal detected
    @Test
    void kidTraversal_detected() {
        String token = jwt("{\"alg\":\"HS256\",\"kid\":\"../../../../etc/passwd\"}",
                "{\"sub\":\"user\"}", "sig");
        var fs = JwtSecurityDetector.detectJwtIssues(token);
        assertTrue(hasFinding(fs, "kid"));
    }

    // 1.2 — benign kid not flagged
    @Test
    void benignKid_notFlagged() {
        String token = jwt("{\"alg\":\"HS256\",\"kid\":\"key-123\"}",
                "{\"sub\":\"user\"}", "sig");
        var fs = JwtSecurityDetector.detectJwtIssues(token);
        assertFalse(hasFinding(fs, "kid"));
    }

    // 1.3 — multiple JWTs both analyzed (regression: previously only first)
    @Test
    void multipleJwts_bothAnalyzed() {
        // First token: alg:none. Second token: has jku. Both must produce findings.
        String t1 = jwt("{\"alg\":\"none\"}", "{\"sub\":\"a\"}", "");
        String t2 = jwt("{\"alg\":\"HS256\",\"jku\":\"https://evil.com/k\"}", "{\"sub\":\"b\"}", "sig");
        String resp = "HTTP/1.1 200\r\n\r\naccess=" + t1 + " refresh=" + t2;
        var fs = JwtSecurityDetector.detectJwtIssues(resp);
        assertTrue(hasFinding(fs, "alg:none"), "first token (alg:none) must be analyzed");
        assertTrue(hasFinding(fs, "jku"), "second token (jku) must be analyzed");
    }

    // 1.3 — duplicate findings across identical JWTs are deduped
    @Test
    void duplicateJwts_deduped() {
        String token = jwt("{\"alg\":\"none\"}", "{\"sub\":\"a\"}", "");
        var fs = JwtSecurityDetector.detectJwtIssues(token + " " + token + " " + token);
        long noneCount = fs.stream().filter(f -> f.title().contains("alg:none")).count();
        assertEquals(1, noneCount, "identical findings should be deduped");
    }

    @Test
    void noJwt_emptyFindings() {
        var fs = JwtSecurityDetector.detectJwtIssues("just some plain text with no tokens");
        assertTrue(fs.isEmpty());
    }
}
