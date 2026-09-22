package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.ErrorCompressor.Diagnosis;
import com.flechazo.apisentinel.ai.agent.ErrorCompressor.FailurePattern;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for P0-5 — the pre-P0-5 {@link ErrorCompressor}
 * matched substrings in the wrong order and hardcoded
 * {@code compressedTokens = 200} regardless of the actual output, which
 * together made it misclassify an English phrasing like "the response
 * was blocked by the WAF" as WAF-blocked (because "blocked" matched
 * before the normal-response branch) and log "compressed 5000→200 tokens"
 * when the compressed diagnosis was actually ~290 tokens (a 70×
 * inflation labelled as compression).
 *
 * <p>These tests pin the new contract:
 * <ul>
 *   <li>Structured JSON fields from {@code SendRequestTool}
 *       ({@code status_code}, {@code waf_detected}, {@code waf_score})
 *       take precedence over any substring match on the response body.</li>
 *   <li>{@code compressedTokens} reflects the actual rendered diagnosis
 *       length rather than a hardcoded literal.</li>
 * </ul>
 */
class ErrorCompressorP05Test {

    private final ErrorCompressor compressor = new ErrorCompressor(new LeveledLogger(null));

    // ============== #A: structured fields beat substring matches ==============

    @Test
    void classify_jsonWithWafDetectedTrue_isAllWafBlocked() {
        // SendRequestTool emits this exact shape when WafDetector fires.
        String result = "{\"status_code\":200, \"waf_detected\":true, \"waf_score\":75, "
                + "\"body\":\"正常业务页面，没有任何 blocked 字样\"}";
        assertThat(compressor.classifySingleResult(result))
                .isEqualTo(FailurePattern.ALL_WAF_BLOCKED);
    }

    @Test
    void classify_jsonWithWafScore30Plus_isAllWafBlocked() {
        // 30-59 is the "needs review" band — for failure classification
        // we treat it as WAF-blocked because the probe didn't reach the
        // backend. Must not be misread as MIXED_ERRORS just because the
        // body contains "200 OK".
        String result = "{\"status_code\":200, \"waf_score\":45, "
                + "\"body\":\"200 OK normal response, not blocked\"}";
        assertThat(compressor.classifySingleResult(result))
                .isEqualTo(FailurePattern.ALL_WAF_BLOCKED);
    }

    @Test
    void classify_json2xxNoAnomaly_isAllNormal_evenWhenBodyContainsBlockedProse() {
        // P0-5's core regression guard: the pre-P0-5 substring matcher
        // read "blocked" in the body and mislabelled a perfectly normal
        // 200 response as WAF-blocked. With the JSON-first path, the
        // unambiguous status_code wins.
        String result = "{\"status_code\":200, \"waf_detected\":false, \"waf_score\":0, "
                + "\"body\":\"the previous request was blocked but this one is fine\"}";
        assertThat(compressor.classifySingleResult(result))
                .isEqualTo(FailurePattern.ALL_NORMAL);
    }

    @Test
    void classify_json2xxWithAnomalyTrue_isMixedErrors() {
        // 2xx on the wire but the tool flagged an anomaly (response-
        // content-based detection) — must NOT be ALL_NORMAL.
        String result = "{\"status_code\":200, \"waf_detected\":false, "
                + "\"anomaly\":true, \"body\":\"database error echoed payload\"}";
        assertThat(compressor.classifySingleResult(result))
                .isEqualTo(FailurePattern.MIXED_ERRORS);
    }

    @Test
    void classify_json401_isAuthFailed() {
        String result = "{\"status_code\":401, \"body\":\"Unauthorized\"}";
        assertThat(compressor.classifySingleResult(result))
                .isEqualTo(FailurePattern.ALL_AUTH_FAILED);
    }

    @Test
    void classify_json429_isRateLimited() {
        String result = "{\"status_code\":429, \"body\":\"rate limit exceeded\"}";
        assertThat(compressor.classifySingleResult(result))
                .isEqualTo(FailurePattern.RATE_LIMITED);
    }

    @Test
    void classify_json500_isMixedErrors() {
        String result = "{\"status_code\":500, \"body\":\"internal server error\"}";
        assertThat(compressor.classifySingleResult(result))
                .isEqualTo(FailurePattern.MIXED_ERRORS);
    }

    @Test
    void classify_malformedJson_fallsBackToSubstring() {
        // Plain-text results from other tools (non-SendRequestTool) still
        // take the substring path. P0-5 didn't remove that branch, just
        // made it the fallback.
        assertThat(compressor.classifySingleResult("401 Unauthorized"))
                .isEqualTo(FailurePattern.ALL_AUTH_FAILED);
        assertThat(compressor.classifySingleResult("waf_detected: true, blocked"))
                .isEqualTo(FailurePattern.ALL_WAF_BLOCKED);
        assertThat(compressor.classifySingleResult("just a normal log line"))
                .isEqualTo(FailurePattern.ALL_NORMAL);
    }

    // ============== #B: compressedTokens reflects actual output ==============

    @Test
    void diagnoseBatch_compressedTokens_isNotHardcodedTo200() {
        // Pre-P0-5, the field was literally `int compressedTokens = 200`
        // regardless of what the diagnosis text said. Post-P0-5 it must
        // track the rendered length (so audit logs don't claim "5000→200"
        // when the truth is "4→290").
        List<String> results = List.of(
                "{\"status_code\":200, \"waf_detected\":false}",
                "{\"status_code\":200, \"waf_detected\":false}",
                "{\"status_code\":200, \"waf_detected\":false}");

        Diagnosis d = compressor.diagnoseBatch(results, "id", "");

        assertThat(d.pattern()).isEqualTo(FailurePattern.ALL_NORMAL);
        // The rendered text is longer than 200 bytes for any non-trivial
        // diagnosis — if the field still reads 200 the hardcode is back.
        assertThat(d.compressedTokens())
                .as("compressedTokens must track the rendered diagnosis length, "
                        + "not a hardcoded literal")
                .isNotEqualTo(200);
        assertThat(d.compressedTokens()).isGreaterThan(10);
        // Sanity: compressedText() length and compressedTokens should be
        // consistent (same estimate function feeds both).
        int expectedEstimate = Math.max(1, d.compressedText().length() / 4);
        assertThat(d.compressedTokens()).isEqualTo(expectedEstimate);
    }

    @Test
    void diagnoseBatch_originalTokens_scalesWithInput() {
        // Pre-P0-5 the estimate used the same r.length()/4 heuristic,
        // which is still fine — but pinning the behaviour here means
        // anyone who switches to a different estimator (e.g. real
        // tokenizer) has to update the assertion intentionally.
        List<String> shortBatch = List.of("short", "text", "here");
        List<String> longBatch = List.of(
                "{\"status_code\":500, \"body\":\"" + "x".repeat(2000) + "\"}",
                "{\"status_code\":500, \"body\":\"" + "y".repeat(2000) + "\"}",
                "{\"status_code\":500, \"body\":\"" + "z".repeat(2000) + "\"}");

        Diagnosis shortD = compressor.diagnoseBatch(shortBatch, "p", "");
        Diagnosis longD = compressor.diagnoseBatch(longBatch, "p", "");

        assertThat(longD.originalTokens()).isGreaterThan(shortD.originalTokens());
    }

    @Test
    void diagnoseBatch_realSendRequestShape_classifiedAsNormal() {
        // End-to-end sanity: a batch shaped like actual SendRequestTool
        // output (200 + no anomaly) must come out as ALL_NORMAL. If the
        // compressor misclassifies this, the reflection trigger fires
        // for the wrong reason and the Agent wastes a turn.
        List<String> results = List.of(
                "{\"status_code\":200, \"waf_detected\":false, \"waf_score\":0, "
                        + "\"anomaly\":false, \"body\":\"{\\\"id\\\":1}\"}",
                "{\"status_code\":200, \"waf_detected\":false, \"waf_score\":0, "
                        + "\"anomaly\":false, \"body\":\"{\\\"id\\\":2}\"}",
                "{\"status_code\":200, \"waf_detected\":false, \"waf_score\":0, "
                        + "\"anomaly\":false, \"body\":\"{\\\"id\\\":3}\"}");

        Diagnosis d = compressor.diagnoseBatch(results, "id", "");
        assertThat(d.pattern()).isEqualTo(FailurePattern.ALL_NORMAL);
    }

    @Test
    void diagnoseBatch_mixedRealShape_isMixedErrors() {
        // When results disagree (some 200, some 403), the batch can't be
        // squeezed into any single pattern → MIXED_ERRORS. The pre-P0-5
        // code did this correctly; pin it so future refactors don't
        // regress.
        List<String> results = List.of(
                "{\"status_code\":200, \"anomaly\":false}",
                "{\"status_code\":403}",
                "{\"status_code\":200, \"anomaly\":true}");

        Diagnosis d = compressor.diagnoseBatch(results, "id", "");
        assertThat(d.pattern()).isEqualTo(FailurePattern.MIXED_ERRORS);
    }
}
