package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.config.SensitiveRule;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

/** 敏感信息检测器——基于 HaE 风格三层规则（主正则+排除+作用域）检测敏感信息泄露。 */
public class SensitiveInfoDetector {

    /** One sensitive match: rule name + matched fragment (truncated). */
    public record SensitiveMatch(String ruleName, String matchedValue) {}

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

    private static void scan(SensitiveRule rule, String text, List<SensitiveMatch> out, List<String> seen) {
        if (text == null || text.isEmpty() || seen.contains(rule.getName())) return;
        Matcher m = rule.getCompiledRegex().matcher(text);
        if (m.find()) {
            String fragment = m.group();
            if (rule.filteredOut(fragment)) return;
            seen.add(rule.getName());
            out.add(new SensitiveMatch(rule.getName(), truncate(fragment)));
        }
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() <= MAX_EVIDENCE_LEN ? s : s.substring(0, MAX_EVIDENCE_LEN) + "…";
    }
}
