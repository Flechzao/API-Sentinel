package com.flechazo.apisentinel.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for P1-6 — the {@link RequestRedactor}.
 *
 * <p>Pre-P1-6 the plugin shipped captured requests to the LLM verbatim,
 * so every live session cookie, bearer token, and custom API key left
 * the local machine in plaintext on every analysis call. These tests
 * pin the redactor's behaviour so a future refactor can't accidentally
 * re-expose credentials.
 */
class RequestRedactorP16Test {

    private static final String RAW_WITH_COOKIE =
            "GET /api/me HTTP/1.1\r\n"
          + "Host: example.com\r\n"
          + "Cookie: sid=abc123def456; theme=dark\r\n"
          + "Accept: */*\r\n\r\n";

    @Test
    void redact_stripsCookieHeader() {
        String redacted = RequestRedactor.redact(RAW_WITH_COOKIE);
        assertThat(redacted)
                .doesNotContain("abc123def456")
                // The full cookie value is redacted; the preview shows
                // the first 4 chars of the value ("sid=") so a human
                // reading the report can still recognise which cookie
                // was present.
                .contains("⟨REDACTED:sid=…");
        // Header name survives — the model still sees that a cookie was
        // present, just not its value.
        assertThat(redacted).contains("Cookie:");
        // Non-sensitive headers pass through untouched.
        assertThat(redacted).contains("Host: example.com");
        assertThat(redacted).contains("Accept: */*");
    }

    @Test
    void redact_stripsAuthorization() {
        String raw = "GET / HTTP/1.1\r\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n\r\n";
        String redacted = RequestRedactor.redact(raw);
        assertThat(redacted)
                .doesNotContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
                .contains("Authorization:")
                .contains("⟨REDACTED:");
    }

    @Test
    void redact_stripsCustomXTokenHeaders() {
        String raw = "POST /login HTTP/1.1\r\n"
                + "X-Session-Token: supersecret1234567890\r\n"
                + "X-Api-Key: ak_live_abcd1234efgh5678\r\n"
                + "X-My-Custom-Header: safe-value\r\n\r\n";
        String redacted = RequestRedactor.redact(raw);
        assertThat(redacted)
                .doesNotContain("supersecret1234567890")
                .doesNotContain("ak_live_abcd1234efgh5678")
                .contains("X-My-Custom-Header: safe-value");
    }

    @Test
    void redact_stripsSetCookieOnResponses() {
        String raw = "HTTP/1.1 200 OK\r\n"
                + "Set-Cookie: session=xyz789; Path=/; HttpOnly\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"ok\":true}";
        String redacted = RequestRedactor.redact(raw);
        assertThat(redacted)
                .doesNotContain("xyz789")
                .contains("Content-Type: application/json")
                // Body is untouched — the LLM still sees the JSON body
                // for analysis purposes.
                .contains("{\"ok\":true}");
    }

    @Test
    void redact_bodyUntouchedEvenWhenItContainsSecrets() {
        // Body redaction is a separate pass (evidence store), not this
        // helper. This test pins that decision so a future refactor
        // doesn't silently break body-based evidence analysis.
        String raw = "POST /login HTTP/1.1\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"username\":\"alice\",\"password\":\"s3cret\"}";
        String redacted = RequestRedactor.redact(raw);
        assertThat(redacted).contains("s3cret");
    }

    @Test
    void redact_idempotent() {
        // Calling redact twice on the same text must not double-redact
        // — otherwise a retry path could mangle already-redacted output
        // into something the model can't reason about.
        String once = RequestRedactor.redact(RAW_WITH_COOKIE);
        String twice = RequestRedactor.redact(once);
        assertThat(twice).isEqualTo(once);
    }

    @Test
    void redact_handlesEmptyAndNull() {
        assertThat(RequestRedactor.redact(null)).isNull();
        assertThat(RequestRedactor.redact("")).isEmpty();
    }

    @Test
    void redact_handlesRequestWithoutHeaders() {
        // A bare request line — no headers to strip.
        String raw = "GET / HTTP/1.1\r\n\r\n";
        assertThat(RequestRedactor.redact(raw)).isEqualTo(raw);
    }

    @Test
    void redact_handlesCaseInsensitiveHeaderNames() {
        // Some frameworks emit upper-case header names.
        String raw = "GET / HTTP/1.1\r\n"
                + "AUTHORIZATION: Bearer abc123xyz456\r\n\r\n";
        String redacted = RequestRedactor.redact(raw);
        assertThat(redacted).doesNotContain("abc123xyz456");
    }

    @Test
    void isSensitive_recognisesAllAlwaysSensitiveNames() {
        for (String name : RequestRedactor.sensitiveHeaderNames()) {
            assertThat(RequestRedactor.isSensitive(name))
                    .as("always-sensitive name '%s' must be flagged", name)
                    .isTrue();
        }
    }

    @Test
    void isSensitive_recognisesCustomSuffixPatterns() {
        assertThat(RequestRedactor.isSensitive("X-Firebase-Token")).isTrue();
        assertThat(RequestRedactor.isSensitive("X-Access-Key")).isTrue();
        assertThat(RequestRedactor.isSensitive("X-Client-Secret")).isTrue();
        assertThat(RequestRedactor.isSensitive("X-Service-Credential")).isTrue();
    }

    @Test
    void isSensitive_ignoresBenignHeaders() {
        assertThat(RequestRedactor.isSensitive("Content-Type")).isFalse();
        assertThat(RequestRedactor.isSensitive("Accept-Language")).isFalse();
        assertThat(RequestRedactor.isSensitive("User-Agent")).isFalse();
        assertThat(RequestRedactor.isSensitive("Host")).isFalse();
    }

    @Test
    void redactedValue_fingerprintIsDeterministic() {
        String a = RequestRedactor.redactedValue("same-credential");
        String b = RequestRedactor.redactedValue("same-credential");
        assertThat(a).isEqualTo(b);
        // And different credentials get different fingerprints.
        String c = RequestRedactor.redactedValue("different-credential");
        assertThat(a).isNotEqualTo(c);
    }

    @Test
    void redactedValue_preservesFirstFourChars() {
        // The first-four preview helps humans reading the report
        // visually recognise the cookie without exposing it.
        String r = RequestRedactor.redactedValue("abc1234567890");
        assertThat(r).startsWith("⟨REDACTED:abc1…");
        assertThat(r).endsWith("⟩");
    }

    @Test
    void redactedValue_handlesShortValues() {
        // A one-char credential (rare but possible) shouldn't crash.
        String r = RequestRedactor.redactedValue("x");
        assertThat(r).startsWith("⟨REDACTED:x…");
    }
}
