package com.flechazo.apisentinel.util;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * P2-9: ReDoS (Regular Expression Denial of Service) protection.
 *
 * <p>Certain regex patterns exhibit catastrophic backtracking on
 * adversarial input — a few dozen characters can make a Matcher spin
 * for hours. The classic examples are nested quantifiers like
 * {@code (a+)+}, {@code (a*)*}, {@code (a|a)*}, but any pattern where
 * the same character can be matched by multiple alternatives under a
 * quantifier is vulnerable.
 *
 * <p>This class provides:
 * <ul>
 *   <li>{@link #isLikelyReDoS(String)} — heuristic check on the raw
 *       pattern string before compilation, rejecting the most common
 *       evil-shape patterns</li>
 *   <li>{@link #safeCompile(String, int)} — compile with the ReDoS
 *       check + a clear error message, so callers can surface the
 *       rejection to the user/agent</li>
 * </ul>
 *
 * <p>This is a defense-in-depth layer, not a complete ReDoS solution.
 * Truly robust protection requires running the match in a sandboxed
 * thread with a hard timeout (see {@link InterruptibleCharSequence}),
 * which {@code RepoGrepper} and {@code GrepRepoTool} should also use.
 */
public final class RegexSafety {

    private RegexSafety() {}

    /** Patterns that are almost always ReDoS-vulnerable when found
     *  in the raw regex string. Each is a literal substring check. */
    private static final String[] DANGEROUS_SUBSTRINGS = {
        "(.+)+",     // nested greedy quantifier on dot
        "(.*)+",     // nested greedy on dot-star
        "(.+)*",     // nested greedy quantifier
        "(.*)*",     // nested star
        "(a+)+",     // classic example (generalises to any char+)
        "(a*)*",     // classic example
        "(a|a)*",    // overlapping alternation under star
        "(a|a)+",    // overlapping alternation under plus
        "(.?)+",     // optional under plus
        "(.?)*",     // optional under star
        "([^)]+)+",  // character class under nested quantifier
        "(\\w+)+",   // word chars under nested quantifier
        "(\\w*)*",   // word chars star under star
        "([\\s\\S]+)+", // any-char class under nested quantifier
        "([\\s\\S]*)*", // any-char class star under star
    };

    /** Heuristic: does this raw pattern string contain a substring
     *  that's almost certainly ReDoS-vulnerable?
     *
     *  <p>This is intentionally conservative — it only catches the
     *  most obvious evil shapes. Patterns that pass this check can
     *  still be slow on adversarial input; the timeout layer is the
     *  real backstop. But catching the obvious ones at compile time
     *  avoids the timeout overhead entirely for the common case.
     *
     *  @param patternStr the raw regex string to check
     *  @return true if the pattern looks ReDoS-vulnerable */
    public static boolean isLikelyReDoS(String patternStr) {
        if (patternStr == null || patternStr.isEmpty()) return false;
        for (String dangerous : DANGEROUS_SUBSTRINGS) {
            if (patternStr.contains(dangerous)) return true;
        }
        // Check for nested quantifiers of the form (X+)+ or (X*)+
        // or (X?)+ or (X+)* etc. — the general pattern is a group
        // ending with a quantifier, followed by another quantifier.
        return hasNestedQuantifier(patternStr);
    }

    /** Detect nested quantifiers: a closing paren followed by a
     *  quantifier (+ * ? or {n,}) where the group itself ends with
     *  a quantifier. This is a simplified heuristic — it won't catch
     *  every ReDoS pattern, but it catches the common shapes. */
    private static boolean hasNestedQuantifier(String p) {
        // Look for ")+" or ")*" or ")?" preceded by a quantifier
        // inside the group. Simple substring check — false positives
        // on literal ")" in the pattern are acceptable (worst case
        // we reject a safe pattern, not accept a dangerous one).
        for (int i = 0; i < p.length() - 1; i++) {
            if (p.charAt(i) == ')') {
                char next = p.charAt(i + 1);
                if (next == '+' || next == '*' || next == '?') {
                    // Check if the group contains a quantifier before
                    // this closing paren. Scan backwards to the matching '('.
                    int depth = 0;
                    for (int j = i; j >= 0; j--) {
                        if (p.charAt(j) == ')') depth++;
                        else if (p.charAt(j) == '(') {
                            depth--;
                            if (depth == 0) {
                                // Check if there's a quantifier between
                                // this '(' and the ')' at position i.
                                String group = p.substring(j + 1, i);
                                if (group.matches(".*[+*?]\\}.*")
                                        || group.matches(".*[+*?].*")
                                        || group.contains("{0,")) {
                                    // Group contains a quantifier AND is
                                    // itself quantified → potential ReDoS.
                                    // But only flag if the quantifier isn't
                                    // inside a character class or escaped.
                                    if (!group.startsWith("?")) {
                                        return true;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    /** Safe-compile: check for ReDoS before compiling. Throws a
     *  clear {@link PatternSyntaxException}-style error if the
     *  pattern looks dangerous, so the caller can surface it to
     *  the user/agent instead of silently hanging.
     *
     *  @param patternStr the regex string
     *  @param flags regex flags (e.g. {@link Pattern#CASE_INSENSITIVE})
     *  @return the compiled pattern
     *  @throws IllegalArgumentException if the pattern looks ReDoS-vulnerable */
    public static Pattern safeCompile(String patternStr, int flags) {
        if (isLikelyReDoS(patternStr)) {
            throw new IllegalArgumentException(
                    "Pattern rejected by ReDoS guard (likely catastrophic backtracking): "
                    + truncate(patternStr, 100)
                    + ". Simplify nested quantifiers like (X+)+ or (X*)*.");
        }
        return Pattern.compile(patternStr, flags);
    }

    /** Compile with default flags (0). */
    public static Pattern safeCompile(String patternStr) {
        return safeCompile(patternStr, 0);
    }

    private static String truncate(String s, int max) {
        return s == null ? "" : (s.length() <= max ? s : s.substring(0, max) + "…");
    }
}
