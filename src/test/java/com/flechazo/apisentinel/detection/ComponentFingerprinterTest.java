package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for passive component fingerprinting rules. */
class ComponentFingerprinterTest {

    private static String resp(String headers, String body) {
        return "HTTP/1.1 200 OK\r\n" + headers + "\r\n\r\n" + body;
    }

    @Test
    void fastjson_bodyMarker_highRisk() {
        var comps = ComponentFingerprinter.fingerprint(
                resp("Content-Type: application/json", "{\"error\":\"com.alibaba.fastjson.JSONException\"}"),
                "http://t/api/x");
        assertTrue(comps.stream().anyMatch(c -> c.name().equals("Fastjson") && c.risk().equals("HIGH")));
    }

    @Test
    void shiro_rememberMeMarker() {
        var comps = ComponentFingerprinter.fingerprint(
                resp("Set-Cookie: rememberMe=deleteMe", ""), "http://t/");
        assertTrue(comps.stream().anyMatch(c -> c.name().equals("Shiro")));
    }

    @Test
    void actuatorHeapdump_pathMarker() {
        var comps = ComponentFingerprinter.fingerprint(resp("", "{}"),
                "http://t/actuator/heapdump");
        assertTrue(comps.stream().anyMatch(c -> c.name().equals("Spring Actuator heapdump")
                && c.risk().equals("HIGH")));
    }

    @Test
    void nacos_pathMarker() {
        var comps = ComponentFingerprinter.fingerprint(resp("", ""), "http://t/nacos/v1/auth/login");
        assertTrue(comps.stream().anyMatch(c -> c.name().equals("Nacos")));
    }

    @Test
    void cookieFingerprint_jsessionid() {
        var comps = ComponentFingerprinter.fingerprint(
                resp("Set-Cookie: JSESSIONID=abc; Path=/", ""), "http://t/x");
        assertTrue(comps.stream().anyMatch(c -> c.name().equals("Java Servlet")));
    }

    @Test
    void sortedByRisk_highFirst() {
        var comps = ComponentFingerprinter.fingerprint(
                resp("Content-Type: text/html", "wp-content/themes/x com.alibaba.fastjson"),
                "http://t/");
        assertFalse(comps.isEmpty());
        assertEquals("HIGH", comps.get(0).risk(), "highest risk component should sort first");
    }

    @Test
    void dedupByName() {
        var comps = ComponentFingerprinter.fingerprint(
                resp("", "com.alibaba.fastjson fastjson.fastjson"), "http://t/");
        assertEquals(1, comps.stream().filter(c -> c.name().equals("Fastjson")).count());
    }

    @Test
    void noDuplicationWithHeuristicServerVersion() {
        // Server: nginx/1.x is HeuristicDetector's territory — fingerprinter
        // must NOT report it (incremental signals only).
        var comps = ComponentFingerprinter.fingerprint(
                resp("Server: nginx/1.18.0", "<html></html>"), "http://t/");
        assertTrue(comps.stream().noneMatch(c -> c.name().toLowerCase().contains("nginx")));
    }

    @Test
    void emptyOrNullInputs_safe() {
        assertTrue(ComponentFingerprinter.fingerprint(null, null).isEmpty());
        assertDoesNotThrow(() -> ComponentFingerprinter.fingerprint("", ""));
    }

    @Test
    void log4jBody_highRisk() {
        var comps = ComponentFingerprinter.fingerprint(
                resp("", "org.apache.logging.log4j.core.config"), "http://t/");
        assertTrue(comps.stream().anyMatch(c -> c.name().equals("Log4j")));
    }
}
