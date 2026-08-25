package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for WAF block-page fingerprinting. Signatures are distilled from
 * bughunter's waf_response_analyzer.py (MIT) — see docs/THIRD-PARTY.md.
 */
class WafDetectorTest {

    private final WafDetector detector = new WafDetector(new LeveledLogger(null));

    private static String resp(String headers, String body) {
        return "HTTP/1.1 403 Forbidden\r\n" + headers + "\r\n\r\n" + body;
    }

    // ===== Vendor signatures → BLOCKED =====

    @Test
    void cloudflare_error1020_blocked() {
        var r = detector.detect(resp("Server: cloudflare\r\ncf-ray: ABC123-IAD",
                "<html><title>Error 1020</title>Access denied</html>"), 403, 120);
        assertTrue(r.isBlocked());
        assertEquals("cloudflare", r.vendor());
    }

    @Test
    void cloudflare_challengePage_blocked() {
        var r = detector.detect(resp("",
                "<html>Just a moment... Checking your browser</html>"), 403, 150);
        assertTrue(r.isBlocked(), "challenge page should be blocked: " + r.detail());
        assertEquals("cloudflare", r.vendor());
    }

    @Test
    void awsWaf_accessDeniedBody_blocked() {
        var r = detector.detect(resp("x-amzn-requestid: 1-ABCDEF1234567890",
                "<Error><AccessDenied>request blocked</AccessDenied></Error>"), 403, 130);
        assertTrue(r.isBlocked());
        assertEquals("aws-waf", r.vendor());
    }

    @Test
    void imperva_incapsula_blocked() {
        var r = detector.detect(resp("Set-Cookie: visid_incap_123=abc",
                "<script src=\"/_Incapsula_Resource?SWJI=...\"></script>"), 403, 140);
        assertTrue(r.isBlocked());
        assertEquals("imperva", r.vendor());
    }

    @Test
    void akamai_referenceNumber_blocked() {
        var r = detector.detect(resp("Server: AkamaiGHost",
                "<html>Access Denied. You don't have permission. Reference #18.1234abcd</html>"), 403, 110);
        assertTrue(r.isBlocked());
        assertEquals("akamai", r.vendor());
    }

    @Test
    void f5_supportId_blocked() {
        var r = detector.detect(resp("",
                "<html>The requested URL was rejected. Please consult with your administrator. Support ID: 123456789012</html>"),
                403, 200);
        assertTrue(r.isBlocked());
        assertEquals("f5-bigip", r.vendor());
    }

    @Test
    void modsecurity_signature_blocked() {
        var r = detector.detect(resp("", "<html><title>406 Not Acceptable!</title>ModSecurity Action</html>"),
                406, 160);
        assertTrue(r.isBlocked());
        assertEquals("modsecurity", r.vendor());
    }

    // ===== Keyword-only signals → NEEDS_REVIEW =====

    @Test
    void blockTitleOnly_needsReview_notBlocked() {
        // "Access Denied" with no vendor signature: could be a business 403
        // page, so it must land in the review band, not blocked.
        var r = detector.detect(resp("", "<html><title>Access Denied</title></html>"), 403, 300);
        assertTrue(r.isSuspected(), "score should reach review band: " + r.detail());
        assertFalse(r.isBlocked());
        assertNull(r.vendor());
    }

    @Test
    void genericLogIdOnly_needsReview() {
        // "Trace ID" (not "Incident ID" — that phrasing is Imperva's vendor
        // signature and would legitimately fingerprint as a real WAF).
        var r = detector.detect(resp("", "<html>Request rejected. Trace ID: 0a1b2c3d4e5f</html>"),
                403, 300);
        assertTrue(r.score() >= WafDetector.THRESHOLD_REVIEW, "log id + title should reach review: " + r.detail());
        assertFalse(r.isBlocked());
    }

    // ===== Backend / business responses → PASSED =====

    @Test
    void normalJsonApi_passed() {
        String body = "{\"code\":0,\"data\":{\"userId\":42,\"items\":[]}}";
        var r = detector.detect("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body,
                200, 240);
        assertFalse(r.isSuspected(), "business JSON must not be flagged: " + r.detail());
    }

    @Test
    void backend500stackTrace_noSignature_passed() {
        var r = detector.detect(resp("",
                "<html><pre>java.lang.NullPointerException\n\tat com.example.Service.get(Service.java:42)</pre></html>"),
                500, 260);
        assertFalse(r.isSuspected(), "plain backend error is not a WAF page: " + r.detail());
    }

    @Test
    void backend401_noSignature_passed() {
        var r = detector.detect(resp("WWW-Authenticate: Bearer", "{\"error\":\"unauthorized\"}"),
                401, 220);
        assertFalse(r.isSuspected());
    }

    @Test
    void emptyResponse_passed() {
        var r = detector.detect("", 0, 0);
        assertEquals(0, r.score());
        assertFalse(r.isSuspected());
    }

    @Test
    void fastResponseAlone_belowReviewThreshold() {
        // fast_response is only +10 — a fast normal response stays PASSED.
        var r = detector.detect("HTTP/1.1 200 OK\r\n\r\nok", 200, 30);
        assertFalse(r.isSuspected());
        assertTrue(r.score() <= 10);
    }

    // ===== Score composition =====

    @Test
    void vendorMatch_capsAtReasonableScore() {
        var r = detector.detect(resp("cf-ray: xyz", "Error 1020 Attention Required! | Cloudflare blocked"),
                403, 50);
        assertTrue(r.isBlocked());
        assertTrue(r.score() <= 100);
    }

    @Test
    void nullResponse_passed() {
        var r = detector.detect(null, 0, 0);
        assertEquals(0, r.score());
    }
}
