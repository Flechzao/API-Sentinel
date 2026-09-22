package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.config.SensitiveRule;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

/** 敏感信息检测器——基于 HaE 风格三层规则（主正则+排除+作用域）检测敏感信息泄露。
 *
 *  <p><b>P1-6 hardening</b>: the pre-P1-6 {@code SensitiveMatch} stored
 *  the <b>raw matched value</b> (e.g. the actual password, API key,
 *  session cookie). That value was then:
 *  <ul>
 *    <li>Stored in memory and persisted to {@code data.json}</li>
 *    <li>Sent to the LLM in the analysis prompt</li>
 *    <li>Included in the HTML / JSON report</li>
 *    <li>Exposed via MCP to external clients</li>
 *  </ul>
 *  Four exfiltration paths for a single secret. P1-6 changes the record
 *  to store only a SHA-256 fingerprint (first 8 hex chars) + a
 *  first-4/last-4 preview — enough to tell "is this the same secret?"
 *  and "what kind of secret is it?" without re-exposing the full value.
 *  The raw value is never stored, never sent to the LLM, never written
 *  to a report, and never returned via MCP. */
public class SensitiveInfoDetector {

    /** One sensitive match: rule name + SHA-256 fingerprint + preview.
     *
     *  <p><b>fingerprint</b>: first 8 hex chars of SHA-256(rawValue).
     *  Lets the operator tell "the same secret appeared in two places"
     *  without seeing the secret. Two different secrets have ~1 in
     *  4 billion chance of colliding on 8 hex chars.
     *
     *  <p><b>preview</b>: first 4 + last 4 characters of the raw value,
     *  separated by {@code …}. Enough for a human to visually recognise
     *  the secret type (e.g. {@code sk-a…xY9z} looks like a Stripe key,
     *  {@code eyJh…ifQ.} looks like a JWT) without re-exposing it.
     *  Values shorter than 8 chars are fully masked: {@code ****}.
     *
     *  <p><b>offset</b>: character offset where the match started in the
     *  scanned text, so the operator can locate the secret in the raw
     *  traffic without the detector having to store the traffic itself. */
    public record SensitiveMatch(String ruleName, String fingerprint, String preview, int offset) {

        /** Backward-compatible accessor: returns the preview (not the raw
         *  value). Callers that used {@code matchedValue()} pre-P1-6
         *  get the masked preview instead of the raw secret — a safe
         *  default that keeps old code compiling without re-exposing
         *  the secret. */
        public String matchedValue() { return preview; }
    }

    private static final int MAX_EVIDENCE_LEN = 200;

    private final ConfigManager configManager;
    private final LeveledLogger logger;

    public SensitiveInfoDetector(ConfigManager configManager, LeveledLogger logger) {
        this.configManager = configManager;
        this.logger = logger;
    }

    /**
     * Detect sensitive information in captured traffic. Scans the FULL raw
     * messages (status line + headers + body) so secrets leaking via
     * Set-Cookie, X-Auth-Token, Location and other headers are caught too.
     * Each rule's scope decides which side is scanned (response/request/any);
     * matches whose fragment also hits the rule's exclusion filter are
     * dropped. Rule names are de-duplicated across scopes.
     */
    public List<SensitiveMatch> detect(String rawRequest, String rawResponse) {
        return detectWithRules(configManager.getConfig().getSensitiveRules(), rawRequest, rawResponse);
    }

    /** Backward-compatible response-only scan. */
    public List<SensitiveMatch> detect(String rawResponse) {
        return detect(null, rawResponse);
    }

    /** Core scan over an explicit rule list (unit-testable without config). */
    public static List<SensitiveMatch> detectWithRules(List<SensitiveRule> rules,
                                                       String rawRequest, String rawResponse) {
        List<SensitiveMatch> findings = new ArrayList<>();
        if (rules == null || rules.isEmpty()) return findings;
        if ((rawRequest == null || rawRequest.isEmpty())
                && (rawResponse == null || rawResponse.isEmpty())) {
            return findings;
        }
        List<String> seen = new ArrayList<>();
        for (SensitiveRule rule : rules) {
            try {
                switch (rule.getScope()) {
                    case REQUEST -> scan(rule, rawRequest, findings, seen);
                    case RESPONSE -> scan(rule, rawResponse, findings, seen);
                    case ANY -> {
                        scan(rule, rawResponse, findings, seen);
                        scan(rule, rawRequest, findings, seen);
                    }
                }
            } catch (Exception ignored) {
                // A broken rule must never kill the scan loop.
            }
        }
        return findings;
    }

    private static void scan(SensitiveRule rule, String text,
                             List<SensitiveMatch> out, List<String> seen) {
        if (text == null || text.isEmpty() || seen.contains(rule.getName())) return;
        Matcher m = rule.getCompiledRegex().matcher(text);
        if (m.find()) {
            String fragment = m.group();
            if (rule.filteredOut(fragment)) return;
            seen.add(rule.getName());
            // P1-6: store fingerprint + preview, NOT the raw value.
            out.add(new SensitiveMatch(
                    rule.getName(),
                    sha256Fingerprint(fragment),
                    preview(fragment),
                    m.start()));
        }
    }

    /** SHA-256 fingerprint (first 8 hex chars) of the raw matched value.
     *  Used for dedup ("same secret in two places") without exposing
     *  the secret. */
    static String sha256Fingerprint(String raw) {
        if (raw == null || raw.isEmpty()) return "00000000";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(8);
            for (int i = 0; i < 4; i++) sb.append(String.format("%02x", digest[i]));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "00000000";
        }
    }

    /** First-4 + last-4 preview of the raw value, separated by {@code …}.
     *  Values shorter than 4 chars are fully masked as {@code ****}.
     *  Values 4-7 chars long show only the first 4 + {@code ****}.
     *  Values 8+ chars show first-4 + {@code …} + last-4.
     *  The preview is truncated to {@link #MAX_EVIDENCE_LEN} chars so
     *  a long match (e.g. a full JWT) doesn't re-expose the whole token. */
    static String preview(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        String truncated = raw.length() <= MAX_EVIDENCE_LEN
                ? raw : raw.substring(0, MAX_EVIDENCE_LEN) + "…";
        int len = truncated.length();
        if (len < 4) return "****";
        String first4 = truncated.substring(0, 4);
        if (len < 8) return first4 + "****";
        String last4 = truncated.substring(len - 4);
        return first4 + "…" + last4;
    }

}
