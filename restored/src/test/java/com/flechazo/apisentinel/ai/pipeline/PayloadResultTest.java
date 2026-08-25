package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.testgen.model.TestCase;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Backward-compatibility tests for the WAF-extended PayloadResult record. */
class PayloadResultTest {

    private static final TestCase TC = new TestCase("t", "SQLi", "id", "' OR 1=1",
            "GET", "/api", Map.of(), "", "d", "e", "HIGH");

    @Test
    void sixArgConstructor_wafFieldsDefault() {
        PayloadResult pr = new PayloadResult(TC, "req", "resp", 200, 50, true);
        assertNull(pr.wafVendor());
        assertEquals(0, pr.wafScore());
        assertFalse(pr.isWafBlocked());
        assertFalse(pr.isWafSuspected());
        assertEquals(0L, pr.sentAtMs());
        assertEquals(-1, pr.executionIndex());
    }

    @Test
    void eightArgConstructor_wafFieldsDefault() {
        PayloadResult pr = new PayloadResult(TC, "req", "resp", 200, 50, true, 123L, 2);
        assertNull(pr.wafVendor());
        assertEquals(0, pr.wafScore());
        assertEquals(123L, pr.sentAtMs());
        assertEquals(2, pr.executionIndex());
    }

    @Test
    void fullConstructor_carriesWafInfo() {
        PayloadResult pr = new PayloadResult(TC, "req", "resp", 403, 50, false,
                123L, 0, "cloudflare", 85);
        assertEquals("cloudflare", pr.wafVendor());
        assertEquals(85, pr.wafScore());
        assertTrue(pr.isWafBlocked());
        assertTrue(pr.isWafSuspected());
    }

    @Test
    void reviewBand_suspectedButNotBlocked() {
        PayloadResult pr = new PayloadResult(TC, "req", "resp", 403, 50, false,
                0L, -1, null, 45);
        assertTrue(pr.isWafSuspected());
        assertFalse(pr.isWafBlocked());
    }
}
