package com.flechazo.apisentinel.ai.pipeline;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for P1-1 schema enforcement in
 * {@link AnalysisPipeline#parseVerdict}.
 *
 * <p>The model emits free-form risk values ("CRITICAL", "HIGH RISK",
 * "none", "unknown") and occasionally emits empty-shell entries in the
 * confirmed/suspected arrays just to satisfy the schema shape. P1-1
 * normalizes the risk to one of the four enum values the downstream
 * pipeline/UI/persistence actually understand, and drops empty-shell
 * entries rather than propagating them to {@link VerdictValidator}.
 */
class AnalysisPipelineP11Test {

    /** Reflectively call the private normalizeRisk helper. */
    private static String normalize(String raw) throws Exception {
        Method m = AnalysisPipeline.class.getDeclaredMethod("normalizeRisk", String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, raw);
    }

    @Test
    void normalizeRisk_validValuesPassThrough() throws Exception {
        assertThat(normalize("HIGH")).isEqualTo("HIGH");
        assertThat(normalize("MEDIUM")).isEqualTo("MEDIUM");
        assertThat(normalize("LOW")).isEqualTo("LOW");
        assertThat(normalize("SAFE")).isEqualTo("SAFE");
    }

    @Test
    void normalizeRisk_modelInventedValuesDefaultToSafe() throws Exception {
        // Models routinely invent these — they must not propagate
        // downstream and break filters that key on risk.
        assertThat(normalize("CRITICAL")).isEqualTo("SAFE");
        assertThat(normalize("HIGH RISK")).isEqualTo("HIGH");
        assertThat(normalize("MEDIUM-RISK")).isEqualTo("MEDIUM");
        assertThat(normalize("none")).isEqualTo("SAFE");
        assertThat(normalize("unknown")).isEqualTo("SAFE");
        assertThat(normalize("NO_RISK")).isEqualTo("SAFE");
        assertThat(normalize("CLEAN")).isEqualTo("SAFE");
    }

    @Test
    void normalizeRisk_caseAndWhitespaceInsensitive() throws Exception {
        assertThat(normalize("  high  ")).isEqualTo("HIGH");
        assertThat(normalize("Medium")).isEqualTo("MEDIUM");
        assertThat(normalize("low-risk")).isEqualTo("LOW");
        assertThat(normalize("SAFE\n")).isEqualTo("SAFE");
    }

    @Test
    void normalizeRisk_nullAndEmptyDefaultToSafe() throws Exception {
        assertThat(normalize(null)).isEqualTo("SAFE");
        assertThat(normalize("")).isEqualTo("SAFE");
        assertThat(normalize("   ")).isEqualTo("SAFE");
    }

    @Test
    void normalizeRisk_totallyGarbageDefaultsToSafe() throws Exception {
        // If the model emits a completely unrelated string, default to
        // SAFE rather than propagating it and crashing downstream.
        assertThat(normalize("banana")).isEqualTo("SAFE");
        assertThat(normalize("请重试")).isEqualTo("SAFE");
    }
}
