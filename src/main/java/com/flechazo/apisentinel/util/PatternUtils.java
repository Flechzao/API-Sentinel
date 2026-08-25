package com.flechazo.apisentinel.util;

import java.util.regex.Pattern;

public final class PatternUtils {

    private static final Pattern PURE_NUMERIC = Pattern.compile("^\\d+$");
    private static final Pattern UUID_PREFIX = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-.*");
    private static final Pattern LONG_HEX_ID = Pattern.compile("^[0-9a-fA-F]{16,}$");
    /** A segment that CONTAINS a UUID anywhere — catches prefixed IDs like
     * ns_fbdf2c73-..., agent_60c1c3d5-..., tenant-<uuid>, etc. */
    private static final Pattern CONTAINS_UUID = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    /** Prefixed numeric ID like user_123, order-4567 (letter prefix + sep + digits). */
    private static final Pattern PREFIXED_NUMERIC = Pattern.compile("^[a-zA-Z][a-zA-Z0-9]*[_-]\\d{2,}$");

    private PatternUtils() {}

    public static String replaceApiPatterns(String apiPath) {
        String result = apiPath.replace("xxx", "\\d+");
        return result;
    }

    public static String normalizePathForMatching(String path) {
        if (path == null) return "";
        String normalized = path.toLowerCase().trim();
        if (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    public static String[] splitPathSegments(String path) {
        if (path == null || path.isEmpty() || path.equals("/")) {
            return new String[0];
        }
        String clean = path.startsWith("/") ? path.substring(1) : path;
        if (clean.endsWith("/")) {
            clean = clean.substring(0, clean.length() - 1);
        }
        return clean.split("/");
    }

    /**
     * Unified wildcard segment detection. Returns true if the segment looks like a
     * dynamic/variable path component: placeholder ({id}, :id, <id>), numeric ID,
     * UUID, long hex ID, or explicit wildcard (* / \d+).
     * Note: does NOT include "**" (glob-star); use {@link #isGlobStar} for that.
     */
    public static boolean isWildcardSegment(String segment) {
        if (segment == null || segment.isEmpty()) return false;
        // Placeholder patterns commonly used in API definitions
        if (segment.startsWith("{") && segment.endsWith("}")) return true;  // {id}, {userId}
        if (segment.startsWith(":")) return true;                            // :id  (Express-style)
        if (segment.startsWith("<") && segment.endsWith(">")) return true;  // <id> (Flask-style)
        if (PURE_NUMERIC.matcher(segment).matches()) return true;           // pure numeric e.g. "12345"
        if (UUID_PREFIX.matcher(segment).matches()) return true;            // UUID e.g. "550e8400-e29b-..."
        if (CONTAINS_UUID.matcher(segment).find()) return true;             // prefixed UUID e.g. "ns_<uuid>", "agent_<uuid>"
        if (LONG_HEX_ID.matcher(segment).matches()) return true;            // long hex ID e.g. "a1b2c3d4e5f67890"
        if (PREFIXED_NUMERIC.matcher(segment).matches()) return true;       // prefixed numeric e.g. "user_123"
        if (segment.contains("\\d+") || segment.equals("*")) return true;  // explicit wildcard patterns
        return false;
    }

    /**
     * Returns true if the path contains placeholder syntax ({id}, :id, <id>)
     * — NOT dynamic values like numeric/UUID. Used to warn that placeholder
     * patterns don't work under FUZZY (substring) match mode.
     */
    public static boolean hasPlaceholders(String path) {
        if (path == null) return false;
        if (path.contains("{") || path.contains("}")) return true;
        for (String seg : splitPathSegments(path)) {
            if (seg.startsWith(":")) return true;
            if (seg.startsWith("<") && seg.endsWith(">")) return true;
        }
        return false;
    }

    /**
     * Returns true if the segment is a glob-star "**", meaning "match any remaining sub-path".
     * Used to support patterns like /api/v1/admin/** matching /api/v1/admin/users/123.
     */
    public static boolean isGlobStar(String segment) {
        return "**".equals(segment);
    }
}
