package com.flechazo.apisentinel.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for raw-HTTP-text manipulation helpers used by programmatic verifiers. */
class HttpMessageUtilsTest {

    private static final String RAW_GET =
            "GET /api/users?id=1001&name=bob HTTP/1.1\r\n"
          + "Host: example.com\r\n"
          + "Cookie: sid=abc123; theme=dark\r\n\r\n";

    private static final String RAW_JSON =
            "POST /api/login HTTP/1.1\r\n"
          + "Host: example.com\r\n"
          + "Content-Type: application/json\r\n"
          + "Content-Length: 38\r\n\r\n"
          + "{\"username\":\"alice\",\"password\":\"pw\"}";

    @Test
    void headerLookup_caseInsensitive() {
        assertEquals("example.com", HttpMessageUtils.getHeader(RAW_GET, "host"));
        assertEquals("example.com", HttpMessageUtils.getHeader(RAW_GET, "HOST"));
        assertNull(HttpMessageUtils.getHeader(RAW_GET, "X-Missing"));
    }

    @Test
    void replaceOrInsertHeader_replacesExisting_insertsNew() {
        String replaced = HttpMessageUtils.replaceOrInsertHeader(RAW_GET, "Host", "evil.com");
        assertEquals("evil.com", HttpMessageUtils.getHeader(replaced, "Host"));
        String inserted = HttpMessageUtils.replaceOrInsertHeader(RAW_GET, "Origin", "https://evil.example");
        assertEquals("https://evil.example", HttpMessageUtils.getHeader(inserted, "Origin"));
        // body separator intact
        assertEquals("sid=abc123; theme=dark", HttpMessageUtils.getHeader(inserted, "Cookie"));
    }

    @Test
    void requestTarget_andReplace() {
        assertEquals("/api/users?id=1001&name=bob", HttpMessageUtils.requestTarget(RAW_GET));
        String r = HttpMessageUtils.replaceRequestTarget(RAW_GET, "/x?a=1");
        assertTrue(r.startsWith("GET /x?a=1 HTTP/1.1"));
    }

    @Test
    void setQueryParam_replacesAndKeepsOthers() {
        String r = HttpMessageUtils.setQueryParam(RAW_GET, "id", "1001 AND 1=1");
        String target = HttpMessageUtils.requestTarget(r);
        assertTrue(target.contains("id=1001+AND+1%3D1") || target.contains("id=1001%20AND%201%3D1"),
                target);
        assertTrue(target.contains("name=bob"), target);
    }

    @Test
    void parseQueryParams_decoded() {
        var params = HttpMessageUtils.parseQueryParams("/x?a=1&b=hello%20world");
        assertEquals("1", params.get("a"));
        assertEquals("hello world", params.get("b"));
    }

    @Test
    void setJsonField_replacesValue_updatesContentLength() {
        String r = HttpMessageUtils.setJsonField(RAW_JSON, "username", "{\"$ne\":null}");
        String body = HttpMessageUtils.bodyOf(r);
        assertTrue(body.contains("\"$ne\""), body);
        // Content-Length updated to actual body bytes
        int actualLen = body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        assertEquals(String.valueOf(actualLen), HttpMessageUtils.getHeader(r, "Content-Length"));
    }

    @Test
    void setJsonField_nonJsonBody_unchanged() {
        String raw = "POST /x HTTP/1.1\r\nHost: h\r\n\r\nplain=body";
        assertEquals(raw, HttpMessageUtils.setJsonField(raw, "k", "\"v\""));
    }

    @Test
    void setFormParam_replacesValue() {
        String raw = "POST /x HTTP/1.1\r\nHost: h\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&pass=b";
        String r = HttpMessageUtils.setFormParam(raw, "user", "a' OR '1'='1");
        String body = HttpMessageUtils.bodyOf(r);
        assertTrue(body.contains("user=a%27+OR+%271%27%3D%271")
                || body.contains("user=a%27%20OR%20%271%27%3D%271"), body);
        assertTrue(body.contains("pass=b"), body);
    }

    @Test
    void setCookieValue_replacesExisting_appendsMissing() {
        String replaced = HttpMessageUtils.setCookieValue(RAW_GET, "sid", "forged");
        assertEquals("sid=forged; theme=dark", HttpMessageUtils.getHeader(replaced, "Cookie"));
        String appended = HttpMessageUtils.setCookieValue(RAW_GET, "extra", "1");
        assertTrue(HttpMessageUtils.getHeader(appended, "Cookie").contains("extra=1"));
    }

    @Test
    void bodyAndHeaderSections_splitCorrectly() {
        assertEquals("{\"username\":\"alice\",\"password\":\"pw\"}", HttpMessageUtils.bodyOf(RAW_JSON));
        assertFalse(HttpMessageUtils.headerSection(RAW_JSON).contains("alice"));
    }

    // === P1-2: Probe marker tests ===

    @Test
    void addProbeMarker_insertsHeaderAfterRequestLine() {
        String marked = HttpMessageUtils.addProbeMarker(RAW_GET);
        // P1-4: marker value is the session nonce, not the old "probe"
        // constant — asserting the constant here would silently pass
        // even if addProbeMarker stopped marking at all.
        assertTrue(marked.contains("X-Api-Sentinel: " + HttpMessageUtils.probeMarkerValue()));
        // Header should be after the GET line
        int getLineEnd = marked.indexOf('\n');
        int markerPos = marked.indexOf("X-Api-Sentinel");
        assertTrue(markerPos > getLineEnd);
    }

    @Test
    void addProbeMarker_preservesOriginalHeaders() {
        String marked = HttpMessageUtils.addProbeMarker(RAW_GET);
        assertTrue(marked.contains("Host: example.com"));
        assertTrue(marked.contains("Cookie: sid=abc123"));
    }

    @Test
    void addProbeMarker_handlesRequestWithoutHeaders() {
        String minimal = "GET /api/test HTTP/1.1\n";
        String marked = HttpMessageUtils.addProbeMarker(minimal);
        assertTrue(marked.contains("X-Api-Sentinel: " + HttpMessageUtils.probeMarkerValue()));
    }
}
