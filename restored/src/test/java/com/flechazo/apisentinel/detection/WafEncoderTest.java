package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for WAF-evasion payload variant generation. Encoders distilled
 * from bughunter's waf_encoder.py (MIT) — see docs/THIRD-PARTY.md.
 */
class WafEncoderTest {

    // ===== Individual encoders =====

    @Test
    void urlEncode_singleLayer_percentEncodesSpecials() {
        List<WafEncoder.Variant> v = WafEncoder.urlEncode("' OR '1'='1", 1);
        assertEquals(1, v.size());
        assertEquals("url-encode-1x", v.get(0).technique());
        assertEquals("%27%20OR%20%271%27%3D%271", v.get(0).payload());
    }

    @Test
    void urlEncode_multiLayer_encodesPercentSigns() {
        List<WafEncoder.Variant> v = WafEncoder.urlEncode("' OR 1=1", 2);
        assertEquals(2, v.size());
        // Second layer re-encodes the % signs from the first layer.
        assertTrue(v.get(1).payload().startsWith("%2527"), v.get(1).payload());
    }

    @Test
    void sqlCommentInject_splitsKeywords() {
        List<WafEncoder.Variant> v = WafEncoder.sqlCommentInject("SELECT id FROM users");
        assertTrue(v.stream().anyMatch(x -> x.technique().equals("sql-comment-/**/-split")
                && x.payload().contains("S/**/ELECT")), v.toString());
        assertTrue(v.stream().anyMatch(x -> x.technique().equals("sql-mysql-version-comment")
                && x.payload().contains("/*!50000SELECT*/")), v.toString());
    }

    @Test
    void sqlCommentInject_noKeywords_noSplitVariants() {
        List<WafEncoder.Variant> v = WafEncoder.sqlCommentInject("12345");
        assertTrue(v.stream().noneMatch(x -> x.technique().startsWith("sql-comment")), v.toString());
    }

    @Test
    void caseMix_alternatingAndCaseVariants() {
        List<WafEncoder.Variant> v = WafEncoder.caseMix("select");
        assertTrue(v.stream().anyMatch(x -> x.technique().equals("case-alternating")
                && x.payload().equals("SeLeCt")), v.toString());
        assertTrue(v.stream().anyMatch(x -> x.technique().equals("case-upper")
                && x.payload().equals("SELECT")), v.toString());
    }

    @Test
    void operatorSubstitute_orToPipes() {
        List<WafEncoder.Variant> v = WafEncoder.operatorSubstitute("1' OR '1'='1");
        assertTrue(v.stream().anyMatch(x -> x.payload().contains("||")), v.toString());
    }

    @Test
    void base64WrapXss_wrapsPayload() {
        List<WafEncoder.Variant> v = WafEncoder.base64WrapXss("alert(1)");
        assertEquals(3, v.size());
        assertTrue(v.get(0).payload().contains("eval(atob('"));
        assertTrue(v.get(0).payload().endsWith("</script>"));
    }

    @Test
    void nullByte_appendsAndMidVariants() {
        List<WafEncoder.Variant> v = WafEncoder.nullByte("test.php");
        assertEquals(4, v.size());
        assertEquals("test.php%00", v.get(0).payload());
        assertEquals("test%00.php", v.get(3).payload());
    }

    @Test
    void tabNewlineSpace_replacesSpaces() {
        List<WafEncoder.Variant> v = WafEncoder.tabNewlineSpace("a b");
        assertTrue(v.stream().anyMatch(x -> x.payload().equals("a%09b")), v.toString());
        assertTrue(v.stream().anyMatch(x -> x.payload().equals("a/**/b")), v.toString());
    }

    @Test
    void tabNewlineSpace_noSpaces_empty() {
        assertTrue(WafEncoder.tabNewlineSpace("abc").isEmpty());
    }

    @Test
    void unicodeEscape_escapesSpecials() {
        List<WafEncoder.Variant> v = WafEncoder.unicodeEscape("a'b");
        assertTrue(v.stream().anyMatch(x -> x.technique().equals("unicode-js-escape")
                && x.payload().equals("a\\u0027b")), v.toString());
    }

    @Test
    void htmlEntity_encodesSpecials() {
        List<WafEncoder.Variant> v = WafEncoder.htmlEntity("a<b");
        assertTrue(v.stream().anyMatch(x -> x.technique().equals("html-entity-decimal")
                && x.payload().equals("a&#60;b")), v.toString());
    }

    // ===== Category dispatch =====

    @Test
    void encodeVariants_sqli_includesSqlEncoders() {
        List<WafEncoder.Variant> v = WafEncoder.encodeVariants("SQL注入", "' UNION SELECT 1", 20);
        assertTrue(v.stream().anyMatch(x -> x.technique().startsWith("sql-")), v.toString());
        assertTrue(v.stream().anyMatch(x -> x.technique().startsWith("url-encode")), v.toString());
    }

    @Test
    void encodeVariants_xss_includesBase64Wrap() {
        List<WafEncoder.Variant> v = WafEncoder.encodeVariants("XSS", "<script>alert(1)</script>", 30);
        assertTrue(v.stream().anyMatch(x -> x.technique().startsWith("xss-base64")), v.toString());
        assertFalse(v.stream().anyMatch(x -> x.technique().startsWith("sql-")), v.toString());
    }

    @Test
    void encodeVariants_unknownCategory_universalOnly() {
        List<WafEncoder.Variant> v = WafEncoder.encodeVariants("边界测试", "abc", 30);
        assertFalse(v.isEmpty());
        assertFalse(v.stream().anyMatch(x -> x.technique().startsWith("sql-")), v.toString());
        assertFalse(v.stream().anyMatch(x -> x.technique().startsWith("xss-")), v.toString());
    }

    @Test
    void encodeVariants_dropsDuplicatesAndOriginal() {
        List<WafEncoder.Variant> v = WafEncoder.encodeVariants("SQL注入", "' OR '1'='1", 50);
        long distinct = v.stream().map(WafEncoder.Variant::payload).distinct().count();
        assertEquals(v.size(), distinct, "variants must be unique");
        assertTrue(v.stream().noneMatch(x -> x.payload().equals("' OR '1'='1")),
                "original payload must not reappear as a variant");
    }

    @Test
    void encodeVariants_respectsMaxCap() {
        List<WafEncoder.Variant> v = WafEncoder.encodeVariants("SQL注入", "' UNION SELECT password", 3);
        assertEquals(3, v.size());
    }

    @Test
    void encodeVariants_emptyPayload_empty() {
        assertTrue(WafEncoder.encodeVariants("SQL注入", "", 5).isEmpty());
        assertTrue(WafEncoder.encodeVariants("SQL注入", null, 5).isEmpty());
    }
}
