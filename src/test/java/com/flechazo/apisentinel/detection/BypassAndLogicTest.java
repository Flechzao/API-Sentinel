package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for WAF bypass strategy chains and business-logic pure helpers. */
class BypassAndLogicTest {

    // ===== WafBypassEncoder strategy chains =====

    @Test
    void strategiesFor_sqli_includesCaseAndComment() {
        List<WafEncoder.Variant> v = WafBypassEncoder.strategiesFor(
                "sql_injection", "' UNION SELECT 1");
        assertFalse(v.isEmpty());
        assertTrue(v.size() <= WafBypassEncoder.MAX_ATTEMPTS);
        assertTrue(v.stream().anyMatch(x -> x.technique().startsWith("case-")
                || x.technique().startsWith("sql-")), v.toString());
    }

    @Test
    void strategiesFor_ssrf_ipVariants() {
        List<WafEncoder.Variant> v = WafBypassEncoder.strategiesFor(
                "ssrf", "url=http://127.0.0.1/meta");
        assertTrue(v.stream().anyMatch(x -> x.payload().contains("2130706433")));
        assertTrue(v.stream().anyMatch(x -> x.payload().contains("[::1]")
                || x.payload().contains("0x7f.0.0.1")));
    }

    @Test
    void strategiesFor_xss_tagRewrite() {
        List<WafEncoder.Variant> v = WafBypassEncoder.strategiesFor(
                "xss", "<script>alert(1)</script>");
        assertTrue(v.stream().anyMatch(x -> x.technique().startsWith("tag-")), v.toString());
    }

    @Test
    void strategiesFor_pathTraversal_encodings() {
        List<WafEncoder.Variant> v = WafBypassEncoder.strategiesFor(
                "path_traversal", "../../etc/passwd");
        assertTrue(v.stream().anyMatch(x -> x.payload().contains("%2e%2e%2f")));
        assertTrue(v.stream().anyMatch(x -> x.payload().contains("%252e")));
    }

    @Test
    void strategiesFor_cmd_separatorSubstitution() {
        List<WafEncoder.Variant> v = WafBypassEncoder.strategiesFor(
                "command_injection", "; id");
        assertTrue(v.stream().anyMatch(x -> x.payload().contains("|")));
    }

    @Test
    void strategiesFor_unknownType_genericEncodings() {
        List<WafEncoder.Variant> v = WafBypassEncoder.strategiesFor("other", "abc'");
        assertFalse(v.isEmpty());
        assertTrue(v.size() <= WafBypassEncoder.MAX_ATTEMPTS);
    }

    @Test
    void ssrfIpVariants_noLoopbackLeft() {
        var variants = WafBypassEncoder.ssrfIpVariants("http://127.0.0.1/x");
        for (WafEncoder.Variant v : variants) {
            assertFalse(v.technique().startsWith("ip-") && v.payload().contains("127.0.0.1")
                    && !v.technique().equals("ip-dns-rebinding"),
                    "variant should replace loopback: " + v.payload());
        }
    }

    // ===== BusinessLogicVerifier pure helpers =====

    @Test
    void testType_fromInput_parsesAll() {
        assertEquals(BusinessLogicVerifier.TestType.TAMPER_PRICE,
                BusinessLogicVerifier.TestType.fromInput("tamper_price"));
        assertEquals(BusinessLogicVerifier.TestType.CONCURRENT_RACE,
                BusinessLogicVerifier.TestType.fromInput("concurrent_race"));
        assertEquals(BusinessLogicVerifier.TestType.BATCH_ENUMERATE,
                BusinessLogicVerifier.TestType.fromInput("batch_enumeration"));
        assertNull(BusinessLogicVerifier.TestType.fromInput("bogus"));
        assertNull(BusinessLogicVerifier.TestType.fromInput(null));
    }

    @Test
    void guessBusinessField_findsPriceLikeKey() {
        assertEquals("totalPrice", BusinessLogicVerifier.guessBusinessField(
                "{\"itemId\":1,\"totalPrice\":99.5,\"name\":\"x\"}"));
        assertEquals("couponCode", BusinessLogicVerifier.guessBusinessField(
                "{\"couponCode\":\"ABC\"}"));
        assertNull(BusinessLogicVerifier.guessBusinessField("{\"id\":1,\"name\":\"x\"}"));
        assertNull(BusinessLogicVerifier.guessBusinessField("not json"));
    }
}
