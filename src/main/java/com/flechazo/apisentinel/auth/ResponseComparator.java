package com.flechazo.apisentinel.auth;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Compares HTTP responses to determine if two responses are functionally equivalent.
 * Used to detect authorization bypass: if response to request-with-swapped-auth
 * is very similar to the original, the endpoint may be vulnerable.
 */
public class ResponseComparator {

    /** Fields in JSON that commonly change per-request and should be ignored. */
    private static final Set<String> DYNAMIC_JSON_KEYS = Set.of(
            "timestamp", "time", "date", "datetime", "created_at", "updated_at",
            "requestId", "request_id", "traceId", "trace_id", "correlationId",
            "nonce", "csrf", "csrfToken", "csrf_token"
    );

    private static final Pattern DYNAMIC_JSON_PATTERN;
    static {
        StringBuilder sb = new StringBuilder();
        sb.append("\"(?:");
        sb.append(String.join("|", DYNAMIC_JSON_KEYS));
        sb.append(")\"\\s*:\\s*\"[^\"]*\"");
        DYNAMIC_JSON_PATTERN = Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE);
    }

    /**
     * Compare a baseline response with a test response and return a similarity score [0.0, 1.0].
     *
     * @param baseline the original (authenticated) response
     * @param test     the response after swapping auth tokens
     * @return similarity score; 1.0 = identical, 0.0 = completely different
     */
    public static double compare(HttpResponse baseline, HttpResponse test) {
        if (baseline == null || test == null) return 0.0;

        // Quick check: identical status code?
        int baselineStatus = baseline.statusCode();
        int testStatus = test.statusCode();

        // If test returns 401/403 and baseline doesn't, clearly auth works → 0.0
        if ((testStatus == 401 || testStatus == 403) && baselineStatus != 401 && baselineStatus != 403) {
            return 0.0;
        }

        // If test returns 302 redirect (probably to login) and baseline doesn't
        if (testStatus == 302 && baselineStatus != 302) {
            return 0.05;
        }

        double statusScore = (baselineStatus == testStatus) ? 1.0 : 0.2;

        // Body comparison
        String baseBody = cleanBody(baseline.bodyToString());
        String testBody = cleanBody(test.bodyToString());

        double bodyScore;
        if (baseBody.isEmpty() && testBody.isEmpty()) {
            bodyScore = 1.0;
        } else if (baseBody.isEmpty() || testBody.isEmpty()) {
            bodyScore = 0.0;
        } else if (baseBody.equals(testBody)) {
            bodyScore = 1.0;
        } else {
            bodyScore = computeJaccardSimilarity(baseBody, testBody);
        }

        // Content-Length comparison (rough structural match)
        int baseLen = baseBody.length();
        int testLen = testBody.length();
        double lenRatio = (baseLen == 0 && testLen == 0) ? 1.0 :
                (double) Math.min(baseLen, testLen) / Math.max(baseLen, testLen);

        // Weighted combination
        return statusScore * 0.25 + bodyScore * 0.55 + lenRatio * 0.20;
    }

    /**
     * Clean dynamic fields from response body for comparison.
     */
    private static String cleanBody(String body) {
        if (body == null || body.isEmpty()) return "";
        // Remove dynamic JSON fields
        return DYNAMIC_JSON_PATTERN.matcher(body).replaceAll("\"__DYNAMIC__\":\"__REMOVED__\"");
    }

    /**
     * Jaccard similarity based on 3-gram shingling.
     */
    private static double computeJaccardSimilarity(String a, String b) {
        Set<String> shinglesA = buildShingles(a, 3);
        Set<String> shinglesB = buildShingles(b, 3);
        if (shinglesA.isEmpty() && shinglesB.isEmpty()) return 1.0;

        Set<String> intersection = new HashSet<>(shinglesA);
        intersection.retainAll(shinglesB);

        Set<String> union = new HashSet<>(shinglesA);
        union.addAll(shinglesB);

        if (union.isEmpty()) return 1.0;
        return (double) intersection.size() / union.size();
    }

    private static Set<String> buildShingles(String text, int n) {
        Set<String> shingles = new HashSet<>();
        if (text.length() < n) {
            shingles.add(text);
            return shingles;
        }
        for (int i = 0; i <= text.length() - n; i++) {
            shingles.add(text.substring(i, i + n));
        }
        return shingles;
    }

    /**
     * Determine the verdict based on similarity score.
     */
    public static AuthTestResult.AuthVerdict verdictFromSimilarity(double similarity) {
        if (similarity >= 0.85) return AuthTestResult.AuthVerdict.VULNERABLE;
        if (similarity >= 0.60) return AuthTestResult.AuthVerdict.SUSPICIOUS;
        return AuthTestResult.AuthVerdict.SAFE;
    }
}
