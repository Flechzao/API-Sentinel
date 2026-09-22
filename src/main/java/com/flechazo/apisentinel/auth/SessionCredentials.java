package com.flechazo.apisentinel.auth;

import java.util.*;

/**
 * Unified authentication credential bundle extracted from an HTTP request.
 *
 * <p>Pre-auth-bypass-rework the system stored only a {@code Cookie} header
 * string per session, which meant Bearer-token / X-Token / API-key users
 * could not configure or extract their sessions — the "提取为会话 A" action
 * in the history dialog and the "从流量自动检测" button both silently
 * discarded anything that wasn't a Cookie header.
 *
 * <p>This record carries <b>both</b> credential channels so the rest of the
 * pipeline (config persistence, auth test executor, UI display) can treat
 * Cookie-based and header-based sessions identically.
 *
 * @param cookies     parsed Cookie header (key → value); empty map when the
 *                    request has no Cookie header
 * @param authHeaders auth-related non-Cookie headers (Authorization, X-Token,
 *                    X-Auth-Token, X-Access-Token, Token, API-Key, X-API-Key);
 *                    empty map when none are present
 */
public record SessionCredentials(
        Map<String, String> cookies,
        Map<String, String> authHeaders
) {
    public SessionCredentials {
        cookies = cookies == null ? Map.of() : Map.copyOf(cookies);
        authHeaders = authHeaders == null ? Map.of() : Map.copyOf(authHeaders);
    }

    /** A credential bundle with nothing in it. */
    public static final SessionCredentials EMPTY = new SessionCredentials(Map.of(), Map.of());

    /** True when both channels are empty. */
    public boolean isEmpty() {
        return cookies.isEmpty() && authHeaders.isEmpty();
    }

    /** True when at least one channel carries a credential. */
    public boolean hasCredentials() {
        return !cookies.isEmpty() || !authHeaders.isEmpty();
    }

    /**
     * Serialize auth headers to a human-pasteable multi-line string:
     * {@code "Authorization: Bearer eyJ...\nX-Token: abc"}.
     * Used by the config file and the auth-config textarea.
     */
    public String authHeadersToText() {
        if (authHeaders.isEmpty()) return "";
        StringJoiner sj = new StringJoiner("\n");
        authHeaders.forEach((k, v) -> sj.add(k + ": " + v));
        return sj.toString();
    }

    /**
     * Parse a multi-line text block into an auth-header map.
     * Accepts {@code "Key: Value"} or {@code "Key=Value"} per line;
     * blank lines and leading/trailing whitespace are ignored.
     */
    public static Map<String, String> parseAuthHeadersText(String text) {
        Map<String, String> map = new LinkedHashMap<>();
        if (text == null || text.isBlank()) return map;
        for (String line : text.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            int sep = trimmed.indexOf(':');
            if (sep < 0) sep = trimmed.indexOf('=');
            if (sep <= 0) continue;
            String key = trimmed.substring(0, sep).trim();
            String value = trimmed.substring(sep + 1).trim();
            if (!key.isEmpty() && !value.isEmpty()) {
                map.put(key, value);
            }
        }
        return map;
    }

    /**
     * Rebuild a Cookie header value from the cookie map.
     * Returns empty string when there are no cookies.
     */
    public String toCookieHeaderValue() {
        if (cookies.isEmpty()) return "";
        StringJoiner sj = new StringJoiner("; ");
        cookies.forEach((k, v) -> sj.add(k + "=" + v));
        return sj.toString();
    }

    /**
     * One-line preview for UI labels and logs. Shows the most informative
     * credential available — Authorization value first (Bearer tokens are
     * the common case for modern APIs), then the longest cookie.
     */
    public String preview() {
        // Prefer auth header preview
        for (var entry : authHeaders.entrySet()) {
            String v = entry.getValue();
            if (v.length() > 8) {
                return entry.getKey() + "=" + v.substring(0, Math.min(12, v.length())) + "...";
            }
        }
        // Fallback to cookie preview
        for (var entry : cookies.entrySet()) {
            String v = entry.getValue();
            if (v.length() > 8) {
                return entry.getKey() + "=" + v.substring(0, Math.min(6, v.length())) + "...";
            }
        }
        // Nothing useful
        if (!authHeaders.isEmpty()) return authHeaders.keySet().iterator().next() + "=...";
        if (!cookies.isEmpty()) return cookies.keySet().iterator().next() + "=...";
        return "(empty)";
    }
}
