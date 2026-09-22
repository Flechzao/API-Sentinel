package com.flechazo.apisentinel.ai.agent.tool;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Regression guards for P0-9 — {@link SubmitReportTool}'s
 * {@code countFindings / parseFindingCount} was silently returning 0 on
 * any parse error, which let Gate 4 (the "must send real requests"
 * defense) rubber-stamp malformed verdict JSON straight through. The
 * fix is fail-closed: malformed input throws {@link IllegalArgumentException}
 * and the caller surfaces a rejection.
 *
 * <p>These tests pin that contract. If anyone reintroduces the silent
 * zero (e.g. with a "let's be lenient" refactor), the tests fail and
 * the bypass is caught before it ships.
 */
class SubmitReportToolP09Test {

    // ============== Fail-closed: every malformed input must throw ==============

    @Test
    void parseFindingCount_nullInput_throws() {
        assertThatThrownBy(() -> SubmitReportTool.parseFindingCount(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void parseFindingCount_blankInput_throws() {
        assertThatThrownBy(() -> SubmitReportTool.parseFindingCount("   \n\t"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void parseFindingCount_malformedJson_throws() {
        // The exact failure mode §3.7 P0-9 documented: a model spits out
        // unparseable JSON and the gate used to return 0 (silently accept).
        assertThatThrownBy(() -> SubmitReportTool.parseFindingCount("{not json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid JSON");
    }

    @Test
    void parseFindingCount_jsonArray_throws() {
        // A JSON array is syntactically valid but the wrong top-level
        // shape — must be rejected, not treated as "0 findings".
        assertThatThrownBy(() -> SubmitReportTool.parseFindingCount("[1, 2, 3]"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("JSON object");
    }

    @Test
    void parseFindingCount_confirmedVulnsNotArray_throws() {
        assertThatThrownBy(() -> SubmitReportTool.parseFindingCount(
                "{\"confirmed_vulns\": \"not an array\"}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("confirmed_vulns must be an array");
    }

    @Test
    void parseFindingCount_suspectedVulnsNotArray_throws() {
        assertThatThrownBy(() -> SubmitReportTool.parseFindingCount(
                "{\"suspected_vulns\": 42}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("suspected_vulns must be an array");
    }

    // ============== True positives: valid inputs return the right count ==============

    @Test
    void parseFindingCount_emptyObject_returnsZero() {
        // An empty object is legitimate (a SAFE verdict with no findings).
        // The count is 0 AND the call does NOT throw — fail-closed only
        // fires on malformed input, not on empty-but-valid verdicts.
        assertThat(SubmitReportTool.parseFindingCount("{}")).isZero();
    }

    @Test
    void parseFindingCount_confirmedOnly_returnsConfirmedSize() {
        assertThat(SubmitReportTool.parseFindingCount(
                "{\"confirmed_vulns\": [{}, {}, {}]}")).isEqualTo(3);
    }

    @Test
    void parseFindingCount_suspectedOnly_returnsSuspectedSize() {
        assertThat(SubmitReportTool.parseFindingCount(
                "{\"suspected_vulns\": [{}, {}]}")).isEqualTo(2);
    }

    @Test
    void parseFindingCount_both_returnsSum() {
        assertThat(SubmitReportTool.parseFindingCount(
                "{\"confirmed_vulns\": [{}], \"suspected_vulns\": [{}, {}]}"))
                .isEqualTo(3);
    }

    @Test
    void parseFindingCount_unknownExtraFieldsIgnored() {
        // Extra fields (recommendations, summary, etc.) must not confuse
        // the count — they're part of the full verdict schema but not
        // relevant to Gate 4's "did you claim any findings?" check.
        assertThat(SubmitReportTool.parseFindingCount(
                "{\"confirmed_vulns\": [{}], \"summary\": \"x\", \"recommendations\": \"y\"}"))
                .isEqualTo(1);
    }
}
