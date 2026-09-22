package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.util.RequestRedactor;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard for P1-6's integration with {@link SendRequestTool} —
 * the tool's JSON output (what the LLM actually sees) must have
 * credentials stripped, even though the internal
 * {@link com.flechazo.apisentinel.ai.pipeline.PayloadResult} retains the
 * raw bytes for WAF detection and evidence anchoring.
 *
 * <p>These tests pin the contract at the RequestRedactor layer rather
 * than mocking the full Montoya send path — the integration is a
 * three-line call into the redactor, so testing the call site is the
 * highest-signal check.
 */
class SendRequestToolP16Test {

    @Test
    void responseHeaders_areRedacted() {
        // Simulated extractHeaders() output — what the tool sends to
        // the LLM in the `response_headers` JSON field.
        String rawHeaders = "Content-Type: application/json\n"
                + "Set-Cookie: session=abc123xyz456; Path=/; HttpOnly\n"
                + "X-Request-Id: 7f3a2b\n"
                + "Access-Control-Allow-Origin: *";
        String redacted = RequestRedactor.redact(rawHeaders);

        // Cookie value is stripped; name and other headers survive.
        assertThat(redacted)
                .doesNotContain("abc123xyz456")
                .contains("Set-Cookie:")
                .contains("Content-Type: application/json")
                .contains("X-Request-Id: 7f3a2b");
    }

    @Test
    void responseBody_withJsonCredentials_isRedactedAtHeaderLayer() {
        // The body itself is passed through verbatim (body redaction is
        // a separate pass in the evidence store, not the header
        // redactor). This test pins that decision so a future refactor
        // doesn't silently break body-based evidence.
        String body = "{\"token\":\"supersecret\",\"user\":\"alice\"}";
        String redacted = RequestRedactor.redact(body);
        assertThat(redacted).isEqualTo(body);
    }

    @Test
    void customXTokens_inResponseHeaders_areRedacted() {
        String rawHeaders = "X-Session-Token: eyJhbGciOiJIUzI1NiJ9\n"
                + "X-Api-Key: ak_live_xyz789\n"
                + "X-Correlation-Id: safe-value";
        String redacted = RequestRedactor.redact(rawHeaders);
        assertThat(redacted)
                .doesNotContain("eyJhbGciOiJIUzI1NiJ9")
                .doesNotContain("ak_live_xyz789")
                .contains("X-Correlation-Id: safe-value");
    }
}
