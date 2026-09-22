package com.flechazo.apisentinel.auth;

import com.flechazo.apisentinel.auth.AuthTestResult.AuthVerdict;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P2-2: length-adaptive similarity thresholds for the auth-bypass verdict.
 * 3-gram Jaccard on a very short response body (e.g. {@code {"code":0}}) is
 * statistically noisy — any same-shaped small envelope scores high, so a
 * swapped-auth response that merely shares the response wrapper could look
 * like an auth bypass. The fix raises the bar to 0.95/0.80 when the baseline
 * body is under ~200 chars; full-size bodies keep 0.85/0.60.
 */
class ResponseComparatorP2Test {

    @Test
    void fullSizeBody_keepsStandardThresholds() {
        // 0.86 ≥ 0.85 → VULNERABLE on a full-size body.
        assertThat(ResponseComparator.verdictFromSimilarity(0.86, 500))
                .isEqualTo(AuthVerdict.VULNERABLE);
        // 0.60-0.84 → SUSPICIOUS.
        assertThat(ResponseComparator.verdictFromSimilarity(0.70, 500))
                .isEqualTo(AuthVerdict.SUSPICIOUS);
        // < 0.60 → SAFE.
        assertThat(ResponseComparator.verdictFromSimilarity(0.50, 500))
                .isEqualTo(AuthVerdict.SAFE);
    }

    @Test
    void shortBody_requiresHigherBar() {
        // Same 0.86 that's VULNERABLE on a full body is only SUSPICIOUS on a
        // short body (< 200 chars): the 3-gram signal is too noisy to confirm.
        assertThat(ResponseComparator.verdictFromSimilarity(0.86, 100))
                .isEqualTo(AuthVerdict.SUSPICIOUS);
        // Need 0.95 to call a short body VULNERABLE.
        assertThat(ResponseComparator.verdictFromSimilarity(0.96, 100))
                .isEqualTo(AuthVerdict.VULNERABLE);
        // And SUSPICIOUS needs 0.80, not 0.60, on a short body.
        assertThat(ResponseComparator.verdictFromSimilarity(0.61, 100))
                .isEqualTo(AuthVerdict.SAFE);
        assertThat(ResponseComparator.verdictFromSimilarity(0.81, 100))
                .isEqualTo(AuthVerdict.SUSPICIOUS);
    }

    @Test
    void legacyOneArgOverload_preservesOldThresholds() {
        // Callers that don't pass a body length must keep 0.85/0.60.
        assertThat(ResponseComparator.verdictFromSimilarity(0.85))
                .isEqualTo(AuthVerdict.VULNERABLE);
        assertThat(ResponseComparator.verdictFromSimilarity(0.60))
                .isEqualTo(AuthVerdict.SUSPICIOUS);
        assertThat(ResponseComparator.verdictFromSimilarity(0.59))
                .isEqualTo(AuthVerdict.SAFE);
    }

    @Test
    void bodyLengthOf_extractsBodyPastHeaders() {
        assertThat(ResponseComparator.bodyLengthOf(
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nshort"))
                .isEqualTo(5);
        assertThat(ResponseComparator.bodyLengthOf(
                "HTTP/1.1 200 OK\n\nshort"))
                .isEqualTo(5);
        // Header-only → 0.
        assertThat(ResponseComparator.bodyLengthOf(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
                .isEqualTo(0);
        // null / empty → 0.
        assertThat(ResponseComparator.bodyLengthOf(null)).isZero();
        assertThat(ResponseComparator.bodyLengthOf("")).isZero();
    }
}
