package com.flechazo.apisentinel.auth;

import java.util.*;

/**
 * Identifies which Cookie keys / headers are the actual authentication parameters
 * by diffing two sessions and applying noise filtering + feature matching.
 */
public class AuthParamIdentifier {

    /** Known non-auth cookie keys (analytics, preferences, tracking). */
    private static final Set<String> NOISE_KEYS = Set.of(
            "_ga", "_gid", "_gat", "_fbp", "_fbc", "_gcl_au", "_gcl_aw",
            "ab_test", "experiment", "variant",
            "trace_id", "request_id", "x-request-id", "correlation_id",
            "theme", "lang", "locale", "timezone", "preferred_view",
            "_hjid", "_hjSessionUser", "_hjFirstSeen",
            "ajs_anonymous_id", "amplitude_id",
            "__cf_bm", "cf_clearance"
    );

    /**
     * Identify auth parameters by diffing two sessions' cookies.
     *
     * @return list of cookie key names that are likely auth parameters, ordered by confidence
     */
    public static List<String> identifyAuthCookieKeys(SessionInfo sessionA, SessionInfo sessionB) {
        Map<String, String> cookiesA = sessionA.getCookieMap();
        Map<String, String> cookiesB = sessionB.getCookieMap();

        // Step 1: Find all cookie keys whose values differ between sessions
        List<String> diffKeys = new ArrayList<>();
        Set<String> allKeys = new LinkedHashSet<>(cookiesA.keySet());
        allKeys.addAll(cookiesB.keySet());

        for (String key : allKeys) {
            String valA = cookiesA.getOrDefault(key, "");
            String valB = cookiesB.getOrDefault(key, "");
            if (!valA.equals(valB)) {
                diffKeys.add(key);
            }
        }

        // Step 2: Filter noise and score by auth-likelihood
        List<ScoredKey> scored = new ArrayList<>();
        for (String key : diffKeys) {
            if (isNoiseKey(key)) continue;
            int score = computeAuthScore(key, cookiesA.getOrDefault(key, ""), cookiesB.getOrDefault(key, ""));
            if (score > 0) {
                scored.add(new ScoredKey(key, score));
            }
        }

        // Sort by score descending
        scored.sort((a, b) -> Integer.compare(b.score, a.score));
        return scored.stream().map(s -> s.key).toList();
    }

    /**
     * Identify auth-related headers (non-Cookie) that differ between sessions.
     */
    public static List<String> identifyAuthHeaders(SessionInfo sessionA, SessionInfo sessionB) {
        Map<String, String> headersA = sessionA.getAuthHeaders();
        Map<String, String> headersB = sessionB.getAuthHeaders();
        List<String> diff = new ArrayList<>();
        Set<String> allKeys = new LinkedHashSet<>(headersA.keySet());
        allKeys.addAll(headersB.keySet());
        for (String key : allKeys) {
            String valA = headersA.getOrDefault(key, "");
            String valB = headersB.getOrDefault(key, "");
            if (!valA.equals(valB)) {
                diff.add(key);
            }
        }
        return diff;
    }

    private static boolean isNoiseKey(String key) {
        String lower = key.toLowerCase();
        for (String noise : NOISE_KEYS) {
            if (lower.equals(noise) || lower.startsWith(noise)) return true;
        }
        return false;
    }

    /**
     * Score a cookie key's likelihood of being an auth parameter.
     * Higher score = more likely auth.
     */
    private static int computeAuthScore(String key, String valueA, String valueB) {
        int score = 1; // base score for being different
        String lower = key.toLowerCase();

        // Name-based scoring
        if (lower.contains("session"))    score += 10;
        if (lower.contains("token"))      score += 10;
        if (lower.contains("auth"))       score += 10;
        if (lower.contains("jwt"))        score += 10;
        if (lower.contains("sid"))        score += 8;
        if (lower.contains("sso"))        score += 8;
        if (lower.contains("login"))      score += 6;
        if (lower.contains("credential")) score += 6;
        if (lower.equals("jsessionid"))   score += 15;
        if (lower.equals("phpsessid"))    score += 15;
        if (lower.equals("asp.net_sessionid")) score += 15;
        if (lower.equals("connect.sid"))  score += 15;

        // Value-based scoring
        String value = valueA.isEmpty() ? valueB : valueA;
        if (value.startsWith("eyJ"))      score += 8;  // JWT format
        if (value.length() >= 32)         score += 4;  // long random string
        if (value.length() >= 64)         score += 2;  // very long

        return score;
    }

    private record ScoredKey(String key, int score) {}
}
