package com.flechazo.apisentinel.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ProgressQuipsTest {

    @Test
    void toolQuip_knownTool_returnsMeme() {
        String q = ProgressQuips.quipFor("send_request", 1);
        assertNotNull(q);
        assertTrue(q.contains("敲门"), "send_request should map to its quip, got: " + q);
    }

    @Test
    void milestone_overridesToolQuip() {
        // At a milestone count the easter egg wins over the tool quip.
        String q = ProgressQuips.quipFor("send_request", 10);
        assertNotNull(q);
        assertTrue(q.contains("老板") || q.contains("10"), "milestone should win at 10, got: " + q);
    }

    @Test
    void unknownTool_noMilestone_fallsBackToFiller() {
        String q = ProgressQuips.quipFor("some_unknown_tool", 3);
        assertNotNull(q, "filler should always be available");
        assertFalse(q.isBlank());
    }

    @Test
    void nullTool_fallsBackToFiller() {
        String q = ProgressQuips.quipFor(null, 0);
        assertNotNull(q, "null tool should still produce a filler line");
    }

    @Test
    void fillerRotatesByCount() {
        // Different counts cycle through different filler lines (deterministic).
        String a = ProgressQuips.quipFor(null, 0);
        String b = ProgressQuips.quipFor(null, 1);
        assertNotNull(a);
        assertNotNull(b);
        assertNotEquals(a, b, "consecutive counts should rotate to a different filler");
    }

    @Test
    void completionQuip_variesByFindings() {
        String none = ProgressQuips.completionQuip(0, 0);
        String confirmed = ProgressQuips.completionQuip(1, 0);
        String many = ProgressQuips.completionQuip(5, 0);
        String suspectedOnly = ProgressQuips.completionQuip(0, 2);
        assertTrue(none.contains("没有") || none.contains("菜"));
        assertTrue(confirmed.contains("漏洞"));
        assertTrue(many.contains("跑路") || many.contains("漏洞"));
        assertTrue(suspectedOnly.contains("疑似"));
    }

    @Test
    void stageQuip_knownAndUnknown() {
        assertTrue(ProgressQuips.stageQuip(1).contains("阶段1"));
        assertTrue(ProgressQuips.stageQuip(6).contains("阶段6"));
        // Unknown stage falls back to the plain label.
        assertTrue(ProgressQuips.stageQuip(9).contains("阶段 9/6"));
    }

    @Test
    void abortQuip_present() {
        String q = ProgressQuips.abortQuip();
        assertNotNull(q);
        assertFalse(q.isBlank());
    }
}
