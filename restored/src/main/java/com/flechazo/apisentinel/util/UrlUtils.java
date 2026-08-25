package com.flechazo.apisentinel.util;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public final class UrlUtils {

    private UrlUtils() {}

    public static String extractPath(String url) {
        try {
            URI uri = URI.create(url);
            String path = uri.getPath();
            return path != null ? path : "/";
        } catch (Exception e) {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return url;
            int pathStart = url.indexOf('/', schemeEnd + 3);
            if (pathStart < 0) return "/";
            int queryStart = url.indexOf('?', pathStart);
            return queryStart < 0 ? url.substring(pathStart) : url.substring(pathStart, queryStart);
        }
    }

    public static String extractHost(String url) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host == null) return "";
            int port = uri.getPort();
            if (port > 0 && port != 80 && port != 443) {
                return host + ":" + port;
            }
            return host;
        } catch (Exception e) {
            return "";
        }
    }

    public static String urlEncode(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8);
    }

    public static boolean isStaticResource(String path) {
        String lower = path.toLowerCase();
        return lower.endsWith(".js") || lower.endsWith(".css") || lower.endsWith(".png")
                || lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".gif")
                || lower.endsWith(".ico") || lower.endsWith(".svg") || lower.endsWith(".woff")
                || lower.endsWith(".woff2") || lower.endsWith(".ttf") || lower.endsWith(".eot")
                || lower.endsWith(".map");
    }

    public static String stripPort(String domain) {
        if (domain == null) return "";
        return domain.replaceAll(":(443|80)$", "");
    }

    public static String extractHostOnly(String url) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            return host != null ? host : "";
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Determine whether two API paths refer to the same endpoint.
     * Supports placeholder matching: {id}, :id, <id> in either path will match
     * any value (including numeric/UUID) in the same position of the other path.
     * Both paths must have the same number of segments to match.
     */
    public static boolean pathsLikelyMatch(String apiPath, String candidatePath) {
        String a = normalizePathForMatch(apiPath);
        String c = normalizePathForMatch(candidatePath);
        if (a.isEmpty() || c.isEmpty()) return false;
        if (a.equalsIgnoreCase(c)) return true;

        return segmentsMatchWithPlaceholders(a, c);
    }

    /**
     * Segment-by-segment comparison where placeholder segments ({id}, :id, <id>)
     * and dynamic values (numeric, UUID) are treated as wildcards matching any counterpart.
     * E.g. "/api/v1/tickets/{id}/remark" matches "/api/v1/tickets/42/remark".
     */
    private static boolean segmentsMatchWithPlaceholders(String pathA, String pathB) {
        String[] segsA = splitSegments(pathA);
        String[] segsB = splitSegments(pathB);
        if (segsA.length != segsB.length) return false;
        if (segsA.length == 0) return false;

        for (int i = 0; i < segsA.length; i++) {
            String sa = segsA[i];
            String sb = segsB[i];
            if (sa.equalsIgnoreCase(sb)) continue;
            // If either side is a placeholder or dynamic value, treat as wildcard match
            if (isPlaceholderOrDynamic(sa) || isPlaceholderOrDynamic(sb)) continue;
            return false;
        }
        return true;
    }

    /** Check if a path segment is a placeholder ({id}, :id, <id>) or dynamic value (numeric, UUID, long hex). */
    private static boolean isPlaceholderOrDynamic(String segment) {
        return PatternUtils.isWildcardSegment(segment);
    }

    private static String[] splitSegments(String path) {
        if (path == null || path.isEmpty() || path.equals("/")) return new String[0];
        String clean = path.startsWith("/") ? path.substring(1) : path;
        if (clean.endsWith("/")) clean = clean.substring(0, clean.length() - 1);
        if (clean.isEmpty()) return new String[0];
        return clean.split("/");
    }

    private static String normalizePathForMatch(String path) {
        if (path == null) return "";
        String s = path.trim();
        int q = s.indexOf('?');
        if (q >= 0) s = s.substring(0, q);
        while (s.length() > 1 && s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }
}
