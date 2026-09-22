package com.flechazo.apisentinel.ai.pipeline.evidence;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static com.flechazo.apisentinel.ai.pipeline.evidence.EvidenceField.*;

/**
 * Programmatic definition of "what evidence each vulnerability type must
 * bring". This is the structural-completeness layer that runs <b>before</b>
 * {@link com.flechazo.apisentinel.ai.pipeline.VerdictValidator}: the validator
 * checks whether submitted evidence is <i>authentic</i> (payload actually
 * sent, response actually seen); this schema checks whether the <i>required
 * kinds</i> of evidence were brought at all.
 *
 * <p>Shared by both modes:
 * <ul>
 *   <li>External mode — the {@code validate_findings} MCP tool demotes findings
 *       whose required slots are missing;</li>
 *   <li>(future) internal mode — the submit gate can consume the same schema.</li>
 * </ul>
 *
 * <p><b>fail-open</b>: types not registered here return no missing fields, so
 * uncovered vuln types are never blocked — they fall through to the existing
 * VerdictValidator logic unchanged. Initial coverage is the 5 most common
 * types; extend {@link #SCHEMAS} to cover more.
 */
public final class EvidenceSchema {

    private EvidenceSchema() {}

    /** Canonical type key → required/optional evidence. */
    private static final Map<String, EvidenceRequirement> SCHEMAS = Map.of(
            "SQL_INJECTION", new EvidenceRequirement(
                    List.of(BASELINE_RESPONSE, INJECTED_RESPONSE, RESPONSE_DIFF, PAYLOAD_USED),
                    List.of(ERROR_MESSAGE, TIMING_EVIDENCE)),
            "IDOR", new EvidenceRequirement(
                    List.of(SESSION_A_RESPONSE, SESSION_B_RESPONSE, ANONYMOUS_RESPONSE, IDENTITY_PROOF),
                    List.of()),
            "SSRF", new EvidenceRequirement(
                    List.of(PAYLOAD_USED, INJECTED_RESPONSE, INTERNAL_INDICATOR),
                    List.of()),
            "XSS", new EvidenceRequirement(
                    List.of(REFLECTED_PAYLOAD, ENCODING_TEST),
                    List.of()),
            "COMMAND_INJECTION", new EvidenceRequirement(
                    List.of(CANARY_RESPONSE),
                    List.of(TIMING_EVIDENCE)));

    /**
     * Normalize a free-text vuln type ("sqli" / "SQL 注入" / "sql_injection")
     * to a canonical schema key, or {@code null} when no registered schema
     * matches (→ fail-open, not gated).
     */
    public static String normalize(String rawType) {
        if (rawType == null) return null;
        String t = rawType.toLowerCase(Locale.ROOT);
        if (t.contains("sql")) return "SQL_INJECTION";
        // access-control family → IDOR schema
        if (t.contains("idor") || t.contains("越权") || t.contains("未授权")
                || t.contains("unauthor") || t.contains("privilege")
                || t.contains("access control") || t.contains("broken access")) return "IDOR";
        if (t.contains("ssrf") || t.contains("server-side request") || t.contains("服务端请求")) return "SSRF";
        if (t.contains("xss") || t.contains("cross-site script") || t.contains("cross site script")
                || t.contains("跨站脚本")) return "XSS";
        if (t.contains("command inj") || t.contains("os command") || t.contains("命令注入")
                || t.contains("rce") || t.contains("remote code")) return "COMMAND_INJECTION";
        return null;
    }

    /** True when this type has a registered evidence schema (i.e. is gated). */
    public static boolean isCovered(String rawType) {
        String key = normalize(rawType);
        return key != null && SCHEMAS.containsKey(key);
    }

    /** The requirement for a type, or {@code null} when uncovered. */
    public static EvidenceRequirement requirementFor(String rawType) {
        String key = normalize(rawType);
        // Map.of(...) rejects a null key with NPE — guard before lookup.
        return key == null ? null : SCHEMAS.get(key);
    }

    /**
     * Required evidence slots this finding failed to supply. Empty when the
     * finding is complete <b>or</b> when the type is uncovered (fail-open).
     */
    public static List<EvidenceField> missingRequired(String rawType, Set<EvidenceField> submitted) {
        EvidenceRequirement req = requirementFor(rawType);
        if (req == null) return List.of();
        List<EvidenceField> missing = new ArrayList<>();
        for (EvidenceField f : req.required()) {
            if (submitted == null || !submitted.contains(f)) missing.add(f);
        }
        return missing;
    }

    /** Human-readable slot-key list for rejection reasons, e.g.
     *  "baseline_response, injected_response". */
    public static String describe(List<EvidenceField> fields) {
        List<String> keys = new ArrayList<>();
        for (EvidenceField f : fields) keys.add(f.key());
        return String.join(", ", keys);
    }
}
