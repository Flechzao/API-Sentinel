package com.flechazo.apisentinel.util;

import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class BambdaCodeGenTest {

    private static ApiEntry entry(String method, String path, String domain) {
        ApiEntry e = new ApiEntry(method, path);
        e.setDomain(domain);
        return e;
    }

    @Test
    void templatedPath_becomesMatchingRegex() {
        // The core bug fix: {id} must become a regex that matches a live URL.
        String regex = BambdaCodeGen.pathToRegex("/api/users/{id}");
        assertEquals("^/api/users/[^/]+$", regex);
        assertTrue(Pattern.compile(regex).matcher("/api/users/123").matches());
        assertFalse(Pattern.compile(regex).matcher("/api/users/123/roles").matches());
    }

    @Test
    void wildcardPath_becomesRegex() {
        String regex = BambdaCodeGen.pathToRegex("/static/*");
        assertTrue(Pattern.compile(regex).matcher("/static/js/app.js").matches());
    }

    @Test
    void filterMode_templatedEntry_usesPatternNotContains() {
        String code = BambdaCodeGen.generate(entry("GET", "/api/users/{id}", "a.com"));
        assertTrue(code.contains("Pattern p0 = Pattern.compile(\"^/api/users/[^/]+$\""), code);
        assertTrue(code.contains(".matcher(reqPath).matches()"), code);
        assertTrue(code.contains("reqHost.equalsIgnoreCase(\"a.com\")"), code);
        assertTrue(code.trim().endsWith("return matched;"), code);
        assertFalse(code.contains("contains(\"/api/users/{id}\")"), code);
    }

    @Test
    void exactPath_usesEquals() {
        String code = BambdaCodeGen.generate(entry("POST", "/api/login", "a.com"));
        assertTrue(code.contains("reqPath.equals(\"/api/login\")"), code);
        // No method check
        assertFalse(code.contains("reqMethod"), code);
    }

    @Test
    void rpcAction_usesUrlContains() {
        // RPC gateway action (no leading /) → url().contains()
        String code = BambdaCodeGen.generate(entry("POST", "getDataServicePeering", "a.com"));
        assertTrue(code.contains("reqUrl.contains(\"getdataservicepeering\")"), code);
        assertFalse(code.contains("reqPath.equals"), code);
    }

    @Test
    void excludeMode_negates() {
        String code = BambdaCodeGen.generate(entry("GET", "/x", "a.com"), BambdaCodeGen.Mode.EXCLUDE);
        assertTrue(code.trim().endsWith("return !matched;"), code);
    }

    @Test
    void highlightMode_setsColor() {
        String code = BambdaCodeGen.generate(entry("GET", "/x", "a.com"), BambdaCodeGen.Mode.HIGHLIGHT);
        assertTrue(code.contains("setHighlightColor(HighlightColor.RED)"), code);
        assertTrue(code.contains("return true;"), code);
    }

    @Test
    void batch_groupsByDomain() {
        String code = BambdaCodeGen.generateBatch(List.of(
                entry("GET", "/a", "one.com"),
                entry("GET", "/b", "one.com"),
                entry("GET", "/c", "two.com")));
        assertTrue(code.contains("one.com"), code);
        assertTrue(code.contains("two.com"), code);
        // one.com group ORs its two paths together
        assertTrue(code.contains("reqPath.equals(\"/a\")") && code.contains("reqPath.equals(\"/b\")"), code);
    }

    @Test
    void emptySelection_returnsFalse() {
        assertTrue(BambdaCodeGen.generateBatch(List.of()).contains("return false;"));
    }
}
