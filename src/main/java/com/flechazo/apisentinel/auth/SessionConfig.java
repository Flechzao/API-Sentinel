package com.flechazo.apisentinel.auth;

/**
 * A configured auth session with metadata (slot, label, domain scope, privilege level).
 * Used by the auth test executor to run pairwise comparisons between sessions.
 *
 * @param slot        "A", "B", or "C" — identifies this session in reports
 * @param label       user-provided label (e.g. "管理员", "用户A")
 * @param credentials the cookie + auth-header bundle
 * @param domain      domain this session is scoped to; empty = all domains
 * @param level       privilege level: "", "HIGH", "MEDIUM", "LOW"
 */
public record SessionConfig(
        String slot,
        String label,
        SessionCredentials credentials,
        String domain,
        String level,
        String group
) {
    public SessionConfig {
        slot = slot != null ? slot : "";
        label = label != null && !label.isBlank() ? label : "会话 " + slot;
        credentials = credentials != null ? credentials : SessionCredentials.EMPTY;
        domain = domain != null ? domain.trim().toLowerCase() : "";
        level = level != null ? level.trim().toUpperCase() : "";
        group = group != null ? group.trim() : "";
    }

    /** Backward-compatible 5-arg constructor (group defaults to ""). */
    public SessionConfig(String slot, String label, SessionCredentials credentials,
                         String domain, String level) {
        this(slot, label, credentials, domain, level, "");
    }

    /** True when this session is scoped to a specific domain. */
    public boolean hasDomain() {
        return !domain.isEmpty();
    }

    /** True when this session matches the given target domain.
     *  A session with no domain scope matches everything. */
    public boolean matchesDomain(String targetDomain) {
        if (domain.isEmpty()) return true;
        if (targetDomain == null || targetDomain.isEmpty()) return true;
        return domain.equalsIgnoreCase(targetDomain.trim().toLowerCase());
    }

    /** Build a {@link SessionInfo} from this config for the executor. */
    public SessionInfo toSessionInfo() {
        return new SessionInfo("manual-" + slot,
                new java.util.LinkedHashMap<>(credentials.cookies()),
                new java.util.LinkedHashMap<>(credentials.authHeaders()));
    }

    /** Short display label, e.g. "会话 A (Authorization=Bearer ey...)". */
    public String shortLabel() {
        return label + " (" + credentials.preview() + ")";
    }
}
