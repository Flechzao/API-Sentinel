package com.flechazo.apisentinel.codeindex;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Regex patterns for user-controllable "tainted input source" expressions —
 * the counterpart to {@link SinkMap}'s dangerous-sink patterns, used by
 * {@link TaintTracer} to recognize when a backward-traced variable's RHS
 * expression reads directly from request data (query/body/header/path
 * param) and can stop tracing there. Same single-line, regex-heuristic
 * approach as SinkMap — not AST-aware, mixes patterns across languages in
 * one flat list rather than splitting per language (SinkMap does the same).
 */
public final class TaintSourceMap {

    private static final List<Pattern> SOURCE_PATTERNS = List.of(
            // Java: Servlet API / Spring MVC
            Pattern.compile("\\.getParameter\\s*\\("),
            Pattern.compile("\\.getHeader\\s*\\("),
            Pattern.compile("\\.getQueryString\\s*\\("),
            Pattern.compile("\\.getCookies?\\s*\\("),
            Pattern.compile("@RequestParam"),
            Pattern.compile("@PathVariable"),
            Pattern.compile("@RequestBody"),
            Pattern.compile("@RequestHeader"),
            Pattern.compile("@CookieValue"),

            // Python: Flask / Django
            Pattern.compile("request\\.args"),
            Pattern.compile("request\\.form"),
            Pattern.compile("request\\.json"),
            Pattern.compile("request\\.data"),
            Pattern.compile("request\\.values"),
            Pattern.compile("request\\.GET"),
            Pattern.compile("request\\.POST"),
            Pattern.compile("request\\.COOKIES"),
            Pattern.compile("request\\.headers"),

            // Node.js: Express / Koa
            Pattern.compile("req\\.query"),
            Pattern.compile("req\\.body"),
            Pattern.compile("req\\.params"),
            Pattern.compile("req\\.headers"),
            Pattern.compile("req\\.cookies"),
            Pattern.compile("ctx\\.query"),
            Pattern.compile("ctx\\.request\\.body")
    );

    private TaintSourceMap() {}

    /** True when the given expression text (an assignment RHS, or a full
     *  line) matches a known tainted-input-source pattern. */
    public static boolean matchesSource(String expression) {
        if (expression == null || expression.isBlank()) return false;
        for (Pattern p : SOURCE_PATTERNS) {
            if (p.matcher(expression).find()) return true;
        }
        return false;
    }
}
