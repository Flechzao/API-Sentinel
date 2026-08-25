package com.flechazo.apisentinel.ai.pipeline;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolves WHICH endpoint a confirmed/suspected vuln actually belongs to.
 *
 * <p>Cluster-hunting analyses (Agent mode especially) start from one source
 * endpoint but actively probe its siblings — a run started at
 * {@code /api/products/search} may confirm SQLi on {@code /api/users/search}.
 * The verdict itself correctly stays with the run's source entry (the report
 * is the unit of analysis), but for TABLE attribution each confirmed vuln
 * must land on the row of the endpoint it was found on, not on the source's.
 *
 * <p>ConfirmedVuln/SuspectedVuln have no structured endpoint field; the
 * endpoint is recovered from the two free-text fields that reliably carry
 * it: {@code verifyCommand} ("GET /api/users/search?name=...") first, then
 * the title's trailing "（/path）" / "(/path)" marker. Returns null when
 * neither yields a path (the vuln belongs to the source endpoint itself).
 */
public final class VulnEndpointAttributor {

    /** "GET /api/users/search?name=x" → captures method + path. */
    private static final Pattern VERIFY_CMD = Pattern.compile(
            "^\\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+(/[^\\s?]+)");
    /** Trailing "（/api/users/search）" or "(/api/users/search)" in a title. */
    private static final Pattern TITLE_PATH = Pattern.compile(
            "[（(]\\s*(/[^\\s（）()]+)\\s*[）)]\\s*$");

    private VulnEndpointAttributor() {}

    /** Endpoint of a confirmed vuln, or null when it belongs to the source. */
    public static String extractEndpoint(ConfirmedVuln vuln) {
        if (vuln == null) return null;
        return extractEndpoint(vuln.verifyCommand(), vuln.title());
    }

    /** Endpoint of a suspected vuln, or null when it belongs to the source. */
    public static String extractEndpoint(SuspectedVuln vuln) {
        if (vuln == null) return null;
        return extractEndpoint(vuln.verifyCommand(), vuln.title());
    }

    /** Path from verifyCommand ("GET /x?y" → "/x"), falling back to the
     *  title's trailing parenthesized path. Query strings are stripped. */
    public static String extractEndpoint(String verifyCommand, String title) {
        if (verifyCommand != null) {
            Matcher m = VERIFY_CMD.matcher(verifyCommand);
            if (m.find()) return m.group(2);
        }
        if (title != null) {
            Matcher m = TITLE_PATH.matcher(title.trim());
            if (m.find()) return m.group(1);
        }
        return null;
    }

    /** HTTP method from verifyCommand ("GET /x" → "GET"); {@code fallback}
     *  when absent. Used when a vuln needs its own table row created. */
    public static String extractMethod(String verifyCommand, String fallback) {
        if (verifyCommand != null) {
            Matcher m = VERIFY_CMD.matcher(verifyCommand);
            if (m.find()) return m.group(1);
        }
        return fallback;
    }

    /** True when the vuln's resolved endpoint differs from the analyzed
     *  source — i.e. it should be attributed to another row. */
    public static boolean isCrossEndpoint(String sourceApiPath, ConfirmedVuln vuln) {
        return isCrossEndpointLike(sourceApiPath, extractEndpoint(vuln));
    }

    /** True when an already-resolved endpoint points at a different path
     *  than the source (null endpoint = source itself, never cross). */
    public static boolean isCrossEndpointLike(String sourceApiPath, String endpoint) {
        return endpoint != null && !endpoint.equalsIgnoreCase(sourceApiPath);
    }
}
