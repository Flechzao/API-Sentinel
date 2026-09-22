package com.flechazo.apisentinel.auth;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;

/**
 * Represents a unique session discovered from Proxy History.
 * Identified by the fingerprint of authentication-related headers.
 */
public class SessionInfo {

    private final String fingerprint;
    private final Map<String, String> cookieMap;
    private final Map<String, String> authHeaders;
    private final List<ProxyHttpRequestResponse> requests = new ArrayList<>();

    public SessionInfo(String fingerprint, Map<String, String> cookieMap, Map<String, String> authHeaders) {
        this.fingerprint = fingerprint;
        this.cookieMap = cookieMap;
        this.authHeaders = authHeaders;
    }

    public void addRequest(ProxyHttpRequestResponse req) { requests.add(req); }

    /**
     * Refresh the stored cookie/auth-header maps to the latest request's values
     * so per-request rotating tokens (CSRF, sliding session IDs) stay fresh when
     * the auth test later reconstructs headers — stale tokens caused the test to
     * be skipped with a false "session expired" result.
     */
    public void updateLatest(Map<String, String> latestCookies, Map<String, String> latestAuthHeaders) {
        if (latestCookies != null) {
            cookieMap.clear();
            cookieMap.putAll(latestCookies);
        }
        if (latestAuthHeaders != null) {
            authHeaders.clear();
            authHeaders.putAll(latestAuthHeaders);
        }
    }

    public String getFingerprint()                       { return fingerprint; }
    public Map<String, String> getCookieMap()             { return cookieMap; }
    public Map<String, String> getAuthHeaders()           { return authHeaders; }
    public List<ProxyHttpRequestResponse> getRequests()   { return requests; }

    /** Rebuild a full Cookie header string from the cookie map. */
    public String toCookieHeaderValue() {
        StringJoiner sj = new StringJoiner("; ");
        cookieMap.forEach((k, v) -> sj.add(k + "=" + v));
        return sj.toString();
    }

    /**
     * Build a {@link SessionCredentials} bundle from this session's
     * stored cookie map and auth headers. Used by the auth test executor
     * to swap both credential channels during the session-exchange test.
     */
    public SessionCredentials toCredentials() {
        return new SessionCredentials(cookieMap, authHeaders);
    }

    /**
     * Multi-line credential summary for UI display and logs. Shows both
     * Cookie and auth-header channels so Bearer-only sessions don't look
     * empty. Format:
     * <pre>
     *   Cookie: key1=val1; key2=val2
     *   Authorization: Bearer eyJ...
     * </pre>
     * Omits empty channels. Returns "(no credentials)" when both are empty.
     */
    public String toCredentialSummary() {
        StringBuilder sb = new StringBuilder();
        if (!cookieMap.isEmpty()) {
            sb.append("Cookie: ").append(toCookieHeaderValue());
        }
        if (!authHeaders.isEmpty()) {
            if (sb.length() > 0) sb.append("\n");
            StringJoiner sj = new StringJoiner("\n");
            authHeaders.forEach((k, v) -> sj.add(k + ": " + v));
            sb.append(sj);
        }
        return sb.length() > 0 ? sb.toString() : "(no credentials)";
    }

    /** Short display label, e.g. "Session A (Authorization=Bearer ey...)".
     *  Pre-rework this only previewed cookie values, showing a fingerprint
     *  hash for Bearer-only sessions which was useless. */
    public String shortLabel(String label) {
        String preview = new SessionCredentials(cookieMap, authHeaders).preview();
        return label + " (" + preview + ")";
    }
}
