package com.flechazo.apisentinel.config;

import java.util.regex.Pattern;

/**
 * A sensitive-info detection rule.
 *
 * Three-layer format inspired by HaE (gh0stkey/HaE — see docs/THIRD-PARTY.md):
 * primary regex (broad match) → exclusion filter regex (drops false positives
 * by re-matching the matched fragment) → scope (which part of the traffic to
 * scan: response / request / any).
 */
public class SensitiveRule {

    /** Which part of the captured traffic the rule scans. */
    public enum Scope { RESPONSE, REQUEST, ANY }

    private final String name;
    private final String group;
    private final Pattern compiledRegex;
    /** Exclusion filter: when the matched fragment also matches this pattern
     *  the finding is dropped (false-positive suppression). null = no filter. */
    private final Pattern filterRegex;
    private final Scope scope;

    public SensitiveRule(String name, String regex, String group, String filterRegex, Scope scope) {
        this.name = name;
        this.group = group;
        this.compiledRegex = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        this.filterRegex = (filterRegex == null || filterRegex.isBlank())
                ? null : Pattern.compile(filterRegex, Pattern.CASE_INSENSITIVE);
        this.scope = scope == null ? Scope.RESPONSE : scope;
    }

    public SensitiveRule(String name, String regex, String group) {
        this(name, regex, group, null, Scope.RESPONSE);
    }

    public SensitiveRule(String name, String regex) {
        this(name, regex, "default", null, Scope.RESPONSE);
    }

    public String getName() {
        return name;
    }

    public String getGroup() {
        return group;
    }

    public Pattern getCompiledRegex() {
        return compiledRegex;
    }

    public Pattern getFilterRegex() {
        return filterRegex;
    }

    public Scope getScope() {
        return scope;
    }

    public boolean matches(String text) {
        return compiledRegex.matcher(text).find();
    }

    /** True when the matched fragment should be dropped (filter hits it). */
    public boolean filteredOut(String matchedFragment) {
        return filterRegex != null && matchedFragment != null
                && filterRegex.matcher(matchedFragment).find();
    }
}
