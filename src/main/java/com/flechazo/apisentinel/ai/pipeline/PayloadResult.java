package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.testgen.model.TestCase;

/**
 * Result of auto-executing a single test payload against the target.
 *
 * @param sentAtMs       wall-clock millis when the request was sent (for
 *                      time-based blind injection / race-condition analysis);
 *                      0 if unknown.
 * @param executionIndex sequential index of this payload within the batch
 *                      (0-based), preserving send order when the concurrent
 *                      engine collects results out of order; -1 if unknown.
 * @param wafVendor      WAF vendor fingerprint when the response looks like a
 *                      WAF block/challenge page (e.g. "cloudflare"), or null
 *                      when no vendor signature matched. Distilled from
 *                      bughunter's waf_response_analyzer.py (MIT) — see
 *                      detection/WafDetector.java and docs/THIRD-PARTY.md.
 * @param wafScore       WAF-block confidence score: &gt;=60 blocked, 30-59
 *                      needs review, &lt;30 treated as passed through to the
 *                      backend. 0 = no WAF signal at all.
 * @param authSession    (P0-8) identifier of the session / identity that
 *                      sent this request, when known. Used by
 *                      {@link VerdictValidator} to require auth-class
 *                      confirms to cite two requests from <i>different</i>
 *                      sessions against the same endpoint — without this,
 *                      an LLM can claim IDOR off a single request with a
 *                      fabricated "I got alice's data" identity proof.
 *                      Free-form so callers can pass a cookie value, a
 *                      "alice" / "bob" label, or an opaque session id;
 *                      {@code null} means "not identity-tagged" (legacy
 *                      callers, SendRequestTool calls that didn't record
 *                      a session).
 * @param claimedByVerdict (P0-8) true when a post-validation
 *                      {@link VerdictValidator#markConfirmedPayloads} pass
 *                      matched this result to a surviving ConfirmedVuln.
 *                      Replaces the previous behaviour of mutating
 *                      {@link #anomalyDetected()} directly — that rewrite
 *                      destroyed the original observation and made the
 *                      UI's "⚡ 已确认" marker indistinguishable from a
 *                      genuinely-observed anomaly. Display layers should
 *                      render a green check when {@code anomalyDetected
 *                      || claimedByVerdict}; audit / export layers should
 *                      keep the two signals distinct.
 */
public record PayloadResult(
    TestCase testCase,
    String sentRequest,
    String receivedResponse,
    int statusCode,
    long responseTimeMs,
    boolean anomalyDetected,
    long sentAtMs,
    int executionIndex,
    String wafVendor,
    int wafScore,
    String authSession,
    boolean claimedByVerdict
) {
    /** WAF-blocked threshold: the response is a WAF block/challenge page. */
    public static final int WAF_BLOCKED = 60;
    /** WAF needs-review threshold: possibly a WAF or business block page. */
    public static final int WAF_REVIEW = 30;

    /** Backward-compatible constructor (timing fields default to 0 / -1,
     *  WAF fields to null / 0, P0-8 fields to null / false). */
    public PayloadResult(TestCase testCase, String sentRequest, String receivedResponse,
                         int statusCode, long responseTimeMs, boolean anomalyDetected) {
        this(testCase, sentRequest, receivedResponse, statusCode, responseTimeMs,
             anomalyDetected, 0L, -1, null, 0, null, false);
    }

    /** Backward-compatible constructor (WAF fields default to null / 0,
     *  P0-8 fields to null / false). */
    public PayloadResult(TestCase testCase, String sentRequest, String receivedResponse,
                         int statusCode, long responseTimeMs, boolean anomalyDetected,
                         long sentAtMs, int executionIndex) {
        this(testCase, sentRequest, receivedResponse, statusCode, responseTimeMs,
             anomalyDetected, sentAtMs, executionIndex, null, 0, null, false);
    }

    /** Backward-compatible constructor (P0-8 fields default to null / false). */
    public PayloadResult(TestCase testCase, String sentRequest, String receivedResponse,
                         int statusCode, long responseTimeMs, boolean anomalyDetected,
                         long sentAtMs, int executionIndex, String wafVendor, int wafScore) {
        this(testCase, sentRequest, receivedResponse, statusCode, responseTimeMs,
             anomalyDetected, sentAtMs, executionIndex, wafVendor, wafScore, null, false);
    }

    /** True when the response is (confidently) a WAF block/challenge page. */
    public boolean isWafBlocked() {
        return wafScore >= WAF_BLOCKED;
    }

    /** True when the response may be a WAF page and warrants human review. */
    public boolean isWafSuspected() {
        return wafScore >= WAF_REVIEW;
    }

    /** Display-layer helper: the green-check condition that used to ride on
     *  {@link #anomalyDetected()} alone. Call this from UI code so the
     *  marker lights up for both genuinely-observed anomalies and
     *  post-validation confirmed matches — but keep the two signals
     *  distinct for audit / export callers. */
    public boolean showsAsVerified() {
        return anomalyDetected || claimedByVerdict;
    }
}
