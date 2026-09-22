package com.flechazo.apisentinel.util;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Regression guards for P1-4 — the probe marker used to be a constant
 * string ({@code "probe"}), so any external request that happened to
 * carry {@code X-Api-Sentinel: probe} (an attacker reflecting our
 * header, or a coincidental match) was treated as "our own probe" and
 * silently dropped from captured traffic. The agent would then
 * conclude "no traffic" when the truth was "traffic was hidden".
 *
 * <p>P1-4 mints a random 128-bit nonce per JVM session and requires
 * BOTH the header name AND the nonce value to match.
 */
class HttpMessageUtilsP14Test {

    /** Build a minimal mocked HttpRequest with a single header. We
     *  mock rather than use Burp's ByteArray factory because the
     *  factory requires a live Burp runtime — the project's test
     *  suite doesn't spin one up. */
    private static HttpRequest requestWithHeader(String name, String value) {
        HttpRequest req = mock(HttpRequest.class);
        HttpHeader header = mock(HttpHeader.class);
        when(header.name()).thenReturn(name);
        when(header.value()).thenReturn(value);
        when(req.headers()).thenReturn(List.of(header));
        return req;
    }

    private static HttpRequest requestWithoutHeaders() {
        HttpRequest req = mock(HttpRequest.class);
        when(req.headers()).thenReturn(List.of());
        return req;
    }

    @Test
    void probeMarkerValue_is32HexChars() {
        // 16 bytes → 32 hex chars.
        assertThat(HttpMessageUtils.probeMarkerValue()).matches("[0-9a-f]{32}");
    }

    @Test
    void isProbeRequest_acceptsRequestWithCorrectNonce() {
        HttpRequest req = requestWithHeader(
                HttpMessageUtils.PROBE_MARKER_HEADER,
                HttpMessageUtils.probeMarkerValue());
        assertThat(HttpMessageUtils.isProbeRequest(req)).isTrue();
    }

    @Test
    void isProbeRequest_rejectsHeaderNameOnly() {
        // Attacker forgery: right header name, wrong value. Must NOT
        // be treated as our probe.
        HttpRequest req = requestWithHeader(HttpMessageUtils.PROBE_MARKER_HEADER,
                "attacker-guessed-value");
        assertThat(HttpMessageUtils.isProbeRequest(req))
                .as("P1-4: header name alone must not pass — the attacker "
                        + "could reflect our header and hide their own traffic")
                .isFalse();
    }

    @Test
    void isProbeRequest_rejectsPreHardeningConstantValue() {
        // The pre-P1-4 constant was "probe" — any external request still
        // carrying that literal must be rejected after the hardening.
        HttpRequest req = requestWithHeader(HttpMessageUtils.PROBE_MARKER_HEADER, "probe");
        assertThat(HttpMessageUtils.isProbeRequest(req)).isFalse();
    }

    @Test
    void isProbeRequest_rejectsMissingHeader() {
        HttpRequest req = requestWithoutHeaders();
        assertThat(HttpMessageUtils.isProbeRequest(req)).isFalse();
    }

    @Test
    void addProbeMarker_usesSessionNonce_notConstant() {
        // The raw request after addProbeMarker must carry the session
        // nonce, not the old "probe" constant — otherwise the
        // isProbeRequest check would never match on our own traffic.
        String raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        String marked = HttpMessageUtils.addProbeMarker(raw);
        assertThat(marked)
                .contains(HttpMessageUtils.PROBE_MARKER_HEADER + ": "
                        + HttpMessageUtils.probeMarkerValue())
                .doesNotContain(HttpMessageUtils.PROBE_MARKER_HEADER + ": probe");
    }

    @Test
    void probeMarkerValue_stableAcrossCalls() {
        // Same JVM session, same nonce. If this flaps between calls,
        // our own probe requests would stop being recognised.
        String a = HttpMessageUtils.probeMarkerValue();
        String b = HttpMessageUtils.probeMarkerValue();
        assertThat(a).isEqualTo(b);
    }
}
