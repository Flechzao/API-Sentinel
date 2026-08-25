package com.flechazo.apisentinel.auth;

/**
 * Result of a single auth-test round (one modified request sent).
 */
public record AuthTestRound(
    String description,         // e.g. "全量Cookie替换" or "仅替换 JSESSIONID"
    int statusCode,             // response status code
    double similarity,          // body similarity to baseline (0.0 - 1.0)
    String requestSnippet,      // first line of the sent request
    String responseSnippet,     // first 200 chars of response body
    String fullRequest,         // complete raw HTTP request
    String fullResponse         // complete raw HTTP response
) {
    /** Backward-compatible constructor without full request/response. */
    public AuthTestRound(String description, int statusCode, double similarity,
                         String requestSnippet, String responseSnippet) {
        this(description, statusCode, similarity, requestSnippet, responseSnippet, null, null);
    }
}
