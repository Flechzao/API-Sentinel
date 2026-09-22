package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.config.SensitiveRule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for the three-layer sensitive rule engine (primary regex + exclusion
 *  filter + scope), inspired by HaE — see docs/THIRD-PARTY.md. */
class SensitiveInfoDetectorTest {

    private static final String RESP = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";

    @Test
    void primaryMatch_responseScope() {
        var rules = List.of(new SensitiveRule("Shiro", "rememberMe=deleteMe", "指纹"));
        var hits = SensitiveInfoDetector.detectWithRules(rules, null,
                RESP + "Set-Cookie: rememberMe=deleteMe; Path=/");
        assertEquals(1, hits.size());
        assertEquals("Shiro", hits.get(0).ruleName());
        // P1-6: matchedValue() now returns the masked preview, not the
        // raw value. The preview shows first-4 + … + last-4.
        assertTrue(hits.get(0).matchedValue().startsWith("reme"));
        // The raw value must NOT be in any stored field.
        assertFalse(hits.get(0).matchedValue().contains("rememberMe=deleteMe"));
        assertFalse(hits.get(0).fingerprint().contains("rememberMe=deleteMe"));
    }

    @Test
    void requestScope_onlyScansRequest() {
        var rules = List.of(new SensitiveRule("AuthHeader", "Bearer eyabc12345xyz", "指纹",
                null, SensitiveRule.Scope.REQUEST));
        // Token only present in the response → must NOT hit a REQUEST-scoped rule.
        var hits = SensitiveInfoDetector.detectWithRules(rules,
                "GET /x HTTP/1.1\r\nHost: h\r\n\r\n",
                RESP + "token: Bearer eyabc12345xyz");
        assertTrue(hits.isEmpty());
        // Present in the request → hits.
        var hits2 = SensitiveInfoDetector.detectWithRules(rules,
                "GET /x HTTP/1.1\r\nAuthorization: Bearer eyabc12345xyz\r\n\r\n", RESP);
        assertEquals(1, hits2.size());
    }

    @Test
    void anyScope_scansBothSides_dedupByRuleName() {
        var rules = List.of(new SensitiveRule("JWT", "eyJ[a-z0-9]{10,}", "指纹",
                null, SensitiveRule.Scope.ANY));
        // Present in BOTH request and response → still one finding.
        String req = "GET /x HTTP/1.1\r\nAuthorization: Bearer eyJabcdefghij123\r\n\r\n";
        String resp = RESP + "{\"token\":\"eyJabcdefghij123\"}";
        var hits = SensitiveInfoDetector.detectWithRules(rules, req, resp);
        assertEquals(1, hits.size());
    }

    @Test
    void exclusionFilter_dropsFalsePositive() {
        // Email rule with an exclusion filter for static-resource-looking TLDs.
        var rules = List.of(new SensitiveRule("Email",
                "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})", "Basic",
                "\\.(jpe?g|png|gif|svg|css|js)$", SensitiveRule.Scope.RESPONSE));
        // Real email → kept.
        var kept = SensitiveInfoDetector.detectWithRules(rules, null, RESP + "contact: bob@example.com");
        assertEquals(1, kept.size());
        // File-looking match → filtered out.
        var dropped = SensitiveInfoDetector.detectWithRules(rules, null, RESP + "logo@2x.png");
        assertTrue(dropped.isEmpty(), "filter should drop static-asset-looking match");
    }

    @Test
    void builtInYamlRules_loadAndDetectShiroAndPasswd() {
        // Regression on the two highest-value HaE-derived rules.
        var shiro = new SensitiveRule("Shiro RememberMe",
                "(rememberMe=deleteMe|=deleteMe|rememberMe=)", "Fingerprint",
                null, SensitiveRule.Scope.ANY);
        var passwd = new SensitiveRule("Passwd File Leak", "(root:[x*]?:0:0:)", "Maybe Vulnerability");

        var hits = SensitiveInfoDetector.detectWithRules(List.of(shiro, passwd), null,
                RESP + "root:x:0:0:root:/root:/bin/bash\nSet-Cookie: rememberMe=deleteMe");
        assertEquals(2, hits.size());
    }

    @Test
    void evidence_truncatedTo200Chars() {
        String longValue = "A".repeat(500);
        var rules = List.of(new SensitiveRule("Long", "A{500}", "测试"));
        var hits = SensitiveInfoDetector.detectWithRules(rules, null, RESP + longValue);
        assertEquals(1, hits.size());
        assertTrue(hits.get(0).matchedValue().length() <= 201, hits.get(0).matchedValue().length() + "");
        assertTrue(hits.get(0).matchedValue().endsWith("…"));
    }

    @Test
    void emptyInputs_noFindings() {
        var rules = List.of(new SensitiveRule("Good", "needle-token-xyz", "测试"));
        assertTrue(SensitiveInfoDetector.detectWithRules(rules, null, null).isEmpty());
        assertTrue(SensitiveInfoDetector.detectWithRules(rules, "", "").isEmpty());
        assertTrue(SensitiveInfoDetector.detectWithRules(List.of(), "GET / HTTP/1.1\r\n\r\n", RESP).isEmpty());
    }
}
