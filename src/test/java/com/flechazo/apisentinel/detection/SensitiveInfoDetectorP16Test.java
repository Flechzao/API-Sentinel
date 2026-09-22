package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for P1-6 — {@link SensitiveInfoDetector} used to
 * store the raw matched value (e.g. the actual password, API key,
 * session cookie) in {@link SensitiveInfoDetector.SensitiveMatch}.
 * That value was then stored, sent to the LLM, written to reports,
 * and exposed via MCP — four exfiltration paths for a single secret.
 *
 * <p>P1-6 changes the record to store only a SHA-256 fingerprint +
 * first-4/last-4 preview + offset. These tests pin that the raw value
 * is never recoverable from the stored fields.
 */
class SensitiveInfoDetectorP16Test {

    @Test
    void fingerprint_isDeterministic() {
        String fp1 = SensitiveInfoDetector.sha256Fingerprint("sk-ant-abc123");
        String fp2 = SensitiveInfoDetector.sha256Fingerprint("sk-ant-abc123");
        assertThat(fp1).isEqualTo(fp2);
        assertThat(fp1).matches("[0-9a-f]{8}");
    }

    @Test
    void fingerprint_differentSecretsDifferentFingerprints() {
        String fp1 = SensitiveInfoDetector.sha256Fingerprint("password1");
        String fp2 = SensitiveInfoDetector.sha256Fingerprint("password2");
        assertThat(fp1).isNotEqualTo(fp2);
    }

    @Test
    void preview_longValue_showsFirstAndLast4() {
        String preview = SensitiveInfoDetector.preview("sk-ant-api03-abc123def456ghi789");
        assertThat(preview).startsWith("sk-a").endsWith("i789");
        assertThat(preview).contains("…");
        // The full value must NOT appear in the preview.
        assertThat(preview).doesNotContain("abc123def456");
    }

    @Test
    void preview_shortValue_masked() {
        // Values shorter than 4 chars are fully masked.
        assertThat(SensitiveInfoDetector.preview("ab")).isEqualTo("****");
        // Values 4-7 chars show first 4 + ****
        assertThat(SensitiveInfoDetector.preview("abcdefg")).isEqualTo("abcd****");
    }

    @Test
    void preview_exactly8Chars_showsFirstAndLast4() {
        String preview = SensitiveInfoDetector.preview("abcdefgh");
        assertThat(preview).isEqualTo("abcd…efgh");
    }

    @Test
    void preview_emptyAndNull_safe() {
        assertThat(SensitiveInfoDetector.preview(null)).isEmpty();
        assertThat(SensitiveInfoDetector.preview("")).isEmpty();
    }

    @Test
    void fingerprint_emptyAndNull_safe() {
        assertThat(SensitiveInfoDetector.sha256Fingerprint(null)).isEqualTo("00000000");
        assertThat(SensitiveInfoDetector.sha256Fingerprint("")).isEqualTo("00000000");
    }

    @Test
    void matchedValue_backwardCompat_returnsPreviewNotRaw() {
        // Callers that used matchedValue() pre-P1-6 get the masked
        // preview instead of the raw secret — a safe default.
        var match = new SensitiveInfoDetector.SensitiveMatch(
                "API Key", "deadbeef", "sk-a…i789", 42);
        assertThat(match.matchedValue()).isEqualTo("sk-a…i789");
        assertThat(match.matchedValue()).doesNotContain("abc123def456");
    }

    @Test
    void match_doesNotExposeRawValueInAnyField() {
        // The whole point of P1-6: the raw secret must not be
        // recoverable from ANY accessor on the stored record.
        String rawSecret = "super-secret-token-value-12345";
        var match = new SensitiveInfoDetector.SensitiveMatch(
                "Token", SensitiveInfoDetector.sha256Fingerprint(rawSecret),
                SensitiveInfoDetector.preview(rawSecret), 0);
        // None of the stored fields contain the full raw value.
        assertThat(match.ruleName()).doesNotContain(rawSecret);
        assertThat(match.fingerprint()).doesNotContain(rawSecret);
        assertThat(match.preview()).doesNotContain(rawSecret);
        assertThat(match.matchedValue()).doesNotContain(rawSecret);
    }
}
