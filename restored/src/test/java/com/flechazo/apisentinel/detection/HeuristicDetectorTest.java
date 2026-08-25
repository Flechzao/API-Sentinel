package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HeuristicDetectorTest {

    private static HeuristicDetector detector() {
        return new HeuristicDetector(new LeveledLogger(null));
    }

    private static boolean hasFinding(List<HeuristicDetector.HeuristicFinding> fs, String titlePart) {
        return fs.stream().anyMatch(f -> f.title().contains(titlePart));
    }

    // 1.1 — missing security headers flagged on HTML 2xx
    @Test
    void missingSecurityHeaders_flaggedOnHtml2xx() {
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>hi</body></html>";
        var fs = detector().detect("GET", "/x", "", resp, 200);
        assertTrue(hasFinding(fs, "content-security-policy"));
        assertTrue(hasFinding(fs, "strict-transport-security"));
        assertTrue(hasFinding(fs, "x-frame-options"));
        assertTrue(hasFinding(fs, "x-content-type-options"));
    }

    // 1.1 — not flagged when headers present
    @Test
    void securityHeadersPresent_notFlagged() {
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
                "Strict-Transport-Security: max-age=31536000\r\n" +
                "Content-Security-Policy: default-src 'self'\r\n" +
                "X-Frame-Options: DENY\r\n" +
                "X-Content-Type-Options: nosniff\r\n" +
                "Referrer-Policy: no-referrer\r\n\r\n<html></html>";
        var fs = detector().detect("GET", "/x", "", resp, 200);
        assertFalse(hasFinding(fs, "content-security-policy"));
        assertFalse(hasFinding(fs, "x-frame-options"));
    }

    // 1.1 — JSON API responses are not noisy
    @Test
    void securityHeaders_skippedForJsonApi() {
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        var fs = detector().detect("GET", "/x", "", resp, 200);
        assertFalse(hasFinding(fs, "content-security-policy"));
    }

    // 1.1 — non-2xx not flagged
    @Test
    void securityHeaders_skippedForErrorStatus() {
        String resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<html>oops</html>";
        var fs = detector().detect("GET", "/x", "", resp, 500);
        assertFalse(hasFinding(fs, "content-security-policy"));
    }

    // 1.5 — CORS *+credentials is MEDIUM (browser-ignored), not HIGH
    @Test
    void cors_wildcardWithCredentials_isMediumNotHigh() {
        String req = "GET /x HTTP/1.1\r\nOrigin: https://evil.com\r\n\r\n";
        String resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n" +
                "Access-Control-Allow-Credentials: true\r\n\r\nok";
        var fs = detector().detect("GET", "/x", req, resp, 200);
        var cors = fs.stream().filter(f -> f.title().contains("通配符 Origin")).findFirst();
        assertTrue(cors.isPresent());
        assertEquals("MEDIUM", cors.get().risk(), "wildcard+credentials is browser-ignored -> MEDIUM");
    }

    // 1.5 — origin reflection + credentials stays HIGH (actually exploitable)
    @Test
    void cors_originReflectionWithCredentials_isHigh() {
        String req = "GET /x HTTP/1.1\r\nOrigin: https://evil.com\r\n\r\n";
        String resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.com\r\n" +
                "Access-Control-Allow-Credentials: true\r\n\r\nok";
        var fs = detector().detect("GET", "/x", req, resp, 200);
        var cors = fs.stream().filter(f -> f.title().contains("Origin 反射")).findFirst();
        assertTrue(cors.isPresent());
        assertEquals("HIGH", cors.get().risk());
    }

    // 1.6 — Private IP word boundary: digit-adjacent IP is part of a longer
    // numeric token (not a standalone host), so lookbehind skips it.
    @Test
    void privateIp_digitAdjacent_notFlagged() {
        // "0192.168.1.1" — 192.168.1.1 is preceded by digit '0'
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"token\":\"0192.168.1.1ABC\"}";
        var fs = detector().detect("GET", "/x", "", resp, 200);
        assertFalse(hasFinding(fs, "内网 IP"));
    }

    // 1.6 — real standalone private IP still flagged
    @Test
    void privateIp_realAddress_flagged() {
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"internal\":\"Connection refused from 192.168.1.1:5432\"}";
        var fs = detector().detect("GET", "/x", "", resp, 200);
        assertTrue(hasFinding(fs, "内网 IP"));
    }

    // 1.6b — regression: the "10.x.x.x" branch used to share a 2-octet
    // suffix with the 172/192.168 branches (which already bake one octet
    // pair into their alternation), so a real 10.x address matched only 3
    // octets total and truncated e.g. "10.1.20.5" down to "10.1.20".
    @Test
    void privateIp_10DotRange_capturesAllFourOctets() {
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"internal\":\"Connection refused from 10.1.20.5:5432\"}";
        var fs = detector().detect("GET", "/x", "", resp, 200);
        var ipFinding = fs.stream().filter(f -> f.title().contains("内网 IP")).findFirst();
        assertTrue(ipFinding.isPresent());
        assertTrue(ipFinding.get().evidence().contains("10.1.20.5"),
                "evidence should contain the full 4-octet address, got: " + ipFinding.get().evidence());
        assertFalse(ipFinding.get().evidence().endsWith("10.1.20"),
                "evidence should not be truncated to 3 octets");
    }

    // 1.7 — SQL error detection uses precise DB-engine signatures
    @Test
    void sqlError_precisePattern_flagged() {
        String resp = "HTTP/1.1 500\r\nContent-Type: text/plain\r\n\r\n" +
                "You have an error in your SQL syntax; check the manual that " +
                "corresponds to your MySQL server version for the right syntax";
        var fs = detector().detect("GET", "/x", "", resp, 500);
        assertTrue(hasFinding(fs, "数据库错误"));
    }

    // 1.7 — plain mention of "mysql" is NOT flagged (false-positive regression)
    @Test
    void sqlError_plainMention_notFlagged() {
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"db\":\"mysql\",\"description\":\"we use mysql and postgresql databases\"}";
        var fs = detector().detect("GET", "/x", "", resp, 200);
        assertFalse(hasFinding(fs, "数据库错误"));
    }
}
