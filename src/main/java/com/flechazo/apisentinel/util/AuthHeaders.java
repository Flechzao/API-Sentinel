package com.flechazo.apisentinel.util;

import java.util.Set;

/**
 * P3-10: single source of truth for "which HTTP headers carry credentials".
 *
 * <p>Pre-P3-10 there were 4 copies of this set scattered across:
 * <ul>
 *   <li>{@code AuthTestExecutor} (8 headers)</li>
 *   <li>{@code AnalysisPipeline} (14 headers — included x-request-id, x-forwarded-for, x-real-ip)</li>
 *   <li>{@code SendRequestTool} (11 headers)</li>
 *   <li>{@code TrafficSearcher} (11 headers — same as SendRequestTool)</li>
 * </ul>
 *
 * <p>The 4 copies had **already drifted**: AnalysisPipeline treated
 * {@code x-request-id} / {@code x-forwarded-for} / {@code x-real-ip} as
 * auth headers (they're not — they're proxy/routing headers), and
 * AuthTestExecutor was missing {@code x-session-id} / {@code token} /
 * {@code session}. This meant the Agent and the Pipeline were sending
 * different auth header sets when stripping auth — a behavioral-level
 * inconsistency that could cause false negatives or false positives
 * depending on which code path processed the request.
 *
 * <p>This class unifies the definition. Every caller that needs to know
 * "is this header a credential?" now references {@link #AUTH_HEADERS}
 * instead of maintaining its own copy.
 */
public final class AuthHeaders {

    private AuthHeaders() {}

    /** The canonical set of HTTP header names (lowercase) that carry
     *  credentials or session identifiers. Used by:
     *  <ul>
     *    <li>{@code AuthTestExecutor} — to strip auth when testing
     *        unauthorized access</li>
     *    <li>{@code AnalysisPipeline} — to identify auth headers in
     *        captured traffic</li>
     *    <li>{@code SendRequestTool} — to preserve/strip auth when
     *        replaying requests</li>
     *    <li>{@code TrafficSearcher} — to extract auth headers from
     *        proxy history</li>
     *    <li>{@code RequestRedactor} — to redact auth values before
     *        sending to the LLM</li>
     *  </ul>
     *
     *  <p><b>Not included</b> (intentionally, fixing the pre-P3-10
     *  drift):
     *  <ul>
     *    <li>{@code x-request-id} — proxy/routing header, not a
     *        credential</li>
     *    <li>{@code x-forwarded-for} — proxy header, not a credential</li>
     *    <li>{@code x-real-ip} — proxy header, not a credential</li>
     *  </ul> */
    public static final Set<String> AUTH_HEADERS = Set.of(
            "cookie",
            "authorization",
            "proxy-authorization",
            "set-cookie",
            "x-token",
            "x-access-token",
            "x-csrf-token",
            "x-xsrf-token",
            "x-api-key",
            "x-auth-token",
            "x-session-id",
            "x-session-token",
            "token",
            "session"
    );

    /** Case-insensitive membership check. */
    public static boolean isAuthHeader(String headerName) {
        if (headerName == null) return false;
        return AUTH_HEADERS.contains(headerName.toLowerCase(java.util.Locale.ROOT));
    }
}
