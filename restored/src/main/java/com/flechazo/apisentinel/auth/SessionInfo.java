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

    /** Short display label, e.g. "Session A (JSESSIONID=abc1...)" */
    public String shortLabel(String label) {
        String preview = cookieMap.entrySet().stream()
                .filter(e -> e.getValue().length() > 8)
                .map(e -> e.getKey() + "=" + e.getValue().substring(0, 6) + "...")
                .findFirst().orElse(fingerprint.substring(0, Math.min(8, fingerprint.length())));
        return label + " (" + preview + ")";
    }
}
