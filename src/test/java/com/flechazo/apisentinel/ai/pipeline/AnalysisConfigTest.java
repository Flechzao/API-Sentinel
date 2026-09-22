package com.flechazo.apisentinel.ai.pipeline;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for AnalysisConfig record, focusing on the F-1 browserEnabled field
 * and backward-compatible constructors.
 */
class AnalysisConfigTest {

    @Test
    void defaults_hasBrowserDisabled() {
        AnalysisConfig config = AnalysisConfig.defaults();
        assertFalse(config.browserEnabled());
    }

    @Test
    void backwardCompatConstructors_defaultBrowserDisabled() {
        // 3-arg
        AnalysisConfig c3 = new AnalysisConfig(true, 10, true);
        assertFalse(c3.browserEnabled());

        // 19-arg (no codeExecutionAutoApprove)
        AnalysisConfig c19 = new AnalysisConfig(true, 10, true, false,
                "", "", "", "", 100_000, true,
                true, true, false, true, 10, false, true, 3, false);
        assertFalse(c19.browserEnabled());
        assertFalse(c19.codeExecutionAutoApprove());
    }

    @Test
    void withBrowserEnabled_returnsNewConfig() {
        AnalysisConfig base = AnalysisConfig.defaults();
        assertFalse(base.browserEnabled());

        AnalysisConfig enabled = base.withBrowserEnabled(true);
        assertTrue(enabled.browserEnabled());

        // Other fields preserved
        assertEquals(base.useCodeRepo(), enabled.useCodeRepo());
        assertEquals(base.maxPayloads(), enabled.maxPayloads());
        assertEquals(base.contextWindowTokens(), enabled.contextWindowTokens());
    }

    @Test
    void withBrowserEnabled_toggleOff() {
        AnalysisConfig base = AnalysisConfig.defaults().withBrowserEnabled(true);
        assertTrue(base.browserEnabled());

        AnalysisConfig toggled = base.withBrowserEnabled(false);
        assertFalse(toggled.browserEnabled());
    }

    @Test
    void withBrowserEnabled_preservesOtherWithMethods() {
        AnalysisConfig config = AnalysisConfig.defaults()
                .withAuditHighRiskOnly(true)
                .withCodeExecutionAutoApprove(true)
                .withBrowserEnabled(true);

        assertTrue(config.auditHighRiskOnly());
        assertTrue(config.codeExecutionAutoApprove());
        assertTrue(config.browserEnabled());
    }

    @Test
    void canonicalConstructor_acceptsBrowserEnabled() {
        AnalysisConfig config = new AnalysisConfig(
                true, 10, true, false,
                "", "会话 A", "", "会话 B",
                150_000, true,
                true, true, false, true, 10,
                false, true, 3, false, false, true);

        assertTrue(config.browserEnabled());
    }
}
