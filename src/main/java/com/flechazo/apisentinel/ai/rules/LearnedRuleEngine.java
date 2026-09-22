package com.flechazo.apisentinel.ai.rules;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Engine that learns detection rules from confirmed AI vulnerability findings.
 * Rules are persisted to ~/.api-sentinel/learned-rules.json and loaded at startup.
 * Before calling expensive AI analysis, these rules can be checked locally.
 */
public class LearnedRuleEngine {

    private static final Path RULES_FILE = com.flechazo.apisentinel.config.AppPaths.resolve("rules.json");
    /** Legacy files for backward-compatible migration into the merged rules.json. */
    private static final Path LEGACY_RULES_FILE = com.flechazo.apisentinel.config.AppPaths.learnedRulesFile();
    private static final Path LEGACY_FP_FILE = com.flechazo.apisentinel.config.AppPaths.falsePositivesFile();

    private final List<LearnedRule> rules = new CopyOnWriteArrayList<>();
    private final Map<String, Pattern> compiledPatterns = new ConcurrentHashMap<>();
    private final Set<String> falsePositives = ConcurrentHashMap.newKeySet();
    private final LeveledLogger logger;
    private final Gson gson;
    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private final ScheduledExecutorService flushScheduler;

    public LearnedRuleEngine(LeveledLogger logger) {
        this.logger = logger;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.flushScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-rules-flush");
            t.setDaemon(true);
            return t;
        });
        flushScheduler.scheduleAtFixedRate(this::flushIfDirty, 30, 30, TimeUnit.SECONDS);
        loadRules();
    }

    private void markDirty() {
        dirty.set(true);
    }

    private void flushIfDirty() {
        if (dirty.compareAndSet(true, false)) {
            saveRules();
        }
    }

    /**
     * Load rules from disk at startup.
     */
    public void loadRules() {
        // Merged rules.json (rules[] + falsePositives[])
        try {
            if (Files.exists(RULES_FILE)) {
                String json = Files.readString(RULES_FILE);
                JsonObject obj = gson.fromJson(json, JsonObject.class);
                if (obj != null) {
                    if (obj.has("rules") && obj.get("rules").isJsonArray()) {
                        List<LearnedRule> loaded = gson.fromJson(obj.get("rules"),
                                new TypeToken<List<LearnedRule>>() {}.getType());
                        rules.clear();
                        if (loaded != null) rules.addAll(loaded);
                    }
                    if (obj.has("falsePositives") && obj.get("falsePositives").isJsonArray()) {
                        Set<String> loaded = gson.fromJson(obj.get("falsePositives"),
                                new TypeToken<Set<String>>() {}.getType());
                        falsePositives.clear();
                        if (loaded != null) falsePositives.addAll(loaded);
                    }
                    compilePatterns();
                    logger.debug("[规则学习] 加载 %d 条规则 + %d 条误报抑制", rules.size(), falsePositives.size());
                    return;
                }
            }
        } catch (Exception e) {
            logger.warn("[规则学习] 加载 rules.json 失败: %s", e.getMessage());
        }
        // Backward-compatible migration from legacy two-file format
        boolean migrated = false;
        try {
            if (Files.exists(LEGACY_RULES_FILE)) {
                List<LearnedRule> loaded = gson.fromJson(Files.readString(LEGACY_RULES_FILE),
                        new TypeToken<List<LearnedRule>>() {}.getType());
                if (loaded != null) { rules.clear(); rules.addAll(loaded); compilePatterns(); migrated = true; }
                logger.info("[规则学习] 迁移 %d 条旧规则", rules.size());
            }
        } catch (Exception ignored) {}
        try {
            if (Files.exists(LEGACY_FP_FILE)) {
                Set<String> loaded = gson.fromJson(Files.readString(LEGACY_FP_FILE),
                        new TypeToken<Set<String>>() {}.getType());
                if (loaded != null) { falsePositives.clear(); falsePositives.addAll(loaded); migrated = true; }
                logger.info("[规则学习] 迁移 %d 条旧误报抑制", falsePositives.size());
            }
        } catch (Exception ignored) {}
        if (migrated) saveRules(); // persist merged form, old files can be deleted later
    }

    public void saveRules() {
        try {
            Path dir = RULES_FILE.getParent();
            if (dir != null) Files.createDirectories(dir);
            rules.forEach(LearnedRule::syncMatchCount);
            JsonObject obj = new JsonObject();
            obj.add("rules", gson.toJsonTree(rules));
            obj.add("falsePositives", gson.toJsonTree(falsePositives));
            Files.writeString(RULES_FILE, gson.toJson(obj));
            logger.debug("[规则学习] 保存 %d 条规则 + %d 条误报抑制", rules.size(), falsePositives.size());
        } catch (IOException e) {
            logger.error("[规则学习] 保存失败: %s", e.getMessage());
        }
    }

    /**
     * Mark a finding as a false positive so future analysis does not re-raise
     * the same finding (and does not learn a rule from it). Keyed by path + type.
     */
    public void markFalsePositive(String apiPath, String type) {
        if (apiPath == null || type == null) return;
        falsePositives.add(fpKey(apiPath, type));
        markDirty();
        logger.info("[规则学习] 标记误报: %s [%s]", apiPath, type);
    }

    public boolean isFalsePositive(String apiPath, String type) {
        if (apiPath == null || type == null) return false;
        return falsePositives.contains(fpKey(apiPath, type));
    }

    private static String fpKey(String apiPath, String type) {
        return apiPath.trim().toLowerCase() + "|" + type.trim().toLowerCase();
    }

    /**
     * Learn rules from a completed AI analysis result.
     * Called after each successful analysis with confirmed findings.
     *
     * Quality gates:
     * - Only learn from HIGH risk findings (MEDIUM is too noisy)
     * - Confidence must be >= 0.8 (was 0.6)
     * - Pattern must be specific enough (no overly broad matchers)
     * - IDOR rules are never auto-learned (too many false positives from generic ID params)
     */
    public void learnFromAnalysis(String apiPath, AnalysisResult result) {
        if (result == null || !result.isSuccess() || result.findings().isEmpty()) return;

        boolean added = false;
        for (VulnFinding finding : result.findings()) {
            if (finding.confidence() < 0.8) continue;

            String risk = finding.risk();
            if (!"HIGH".equalsIgnoreCase(risk)) continue;

            String type = finding.type() != null ? finding.type().toLowerCase() : "";
            // that match normal API traffic (user_id=123 is everywhere)
            if (type.contains("idor") || type.contains("insecure direct")) continue;

            String pattern = generatePattern(finding);
            if (pattern == null || pattern.isEmpty()) continue;

            if (isPatternTooBroad(pattern)) continue;

            if (isDuplicateRule(finding.type(), pattern)) continue;

            String ruleName = String.format("检查 %s - %s", finding.type(), finding.title());
            LearnedRule rule = new LearnedRule(
                    ruleName,
                    pattern,
                    risk,
                    finding.description(),
                    apiPath,
                    finding.type()
            );

            rules.add(rule);
            compilePattern(rule);
            added = true;

            logger.info("[规则学习] 从 %s 学习新规则: %s", apiPath, ruleName);
        }

        while (rules.size() > 100) {
            LearnedRule oldest = rules.remove(0);
            compiledPatterns.remove(oldest.getPattern());
        }

        if (added) {
            markDirty();
        }
    }

    /**
     * Check request/response against learned rules BEFORE calling AI.
     * Returns list of matched rules (empty if no match).
     */
    public List<LearnedRule> checkRules(String requestData, String responseData) {
        List<LearnedRule> matched = new ArrayList<>();
        String combined = (requestData != null ? requestData : "") + "\n" + (responseData != null ? responseData : "");

        for (LearnedRule rule : rules) {
            Pattern p = compiledPatterns.get(rule.getPattern());
            if (p == null) continue;

            try {
                if (p.matcher(combined).find()) {
                    rule.incrementMatchCount();
                    matched.add(rule);
                }
            } catch (Exception e) {
                // Skip broken patterns
            }
        }

        if (!matched.isEmpty()) {
            markDirty();
        }

        return matched;
    }

    /**
     * Generate a regex pattern from a vulnerability finding.
     */
    private String generatePattern(VulnFinding finding) {
        String type = finding.type() != null ? finding.type().toLowerCase() : "";
        String evidence = finding.evidence() != null ? finding.evidence() : "";

        // Generate patterns based on vulnerability type — only for types with reliable signatures
        if (type.contains("sql") || type.contains("sqli")) {
            return "(?i)(sql\\s*syntax|unclosed\\s+quotation|"
                    + "error\\s+in\\s+your\\s+sql|"
                    + "microsoft\\s+ole\\s+db|"
                    + "sqlstate\\[)";
        }
        if (type.contains("xss") || type.contains("cross-site")) {
            return "(?i)(<script[^>]*>.*?</script>|javascript:\\s*alert|"
                    + "on(error|load)\\s*=\\s*[\"'][^\"']*alert)";
        }
        if (type.contains("ssrf") || type.contains("server-side request")) {
            return "(?i)(169\\.254\\.169\\.254|metadata\\.google|"
                    + "file://|gopher://)";
        }
        if (type.contains("path traversal") || type.contains("lfi") || type.contains("directory")) {
            return "(?i)(\\.\\./\\.\\./\\.\\./|/etc/passwd|c:\\\\windows\\\\system32)";
        }
        if (type.contains("command") || type.contains("rce")) {
            return "(?i)(;\\s*(ls|cat|id|whoami)\\s|\\|\\s*(ls|cat|id)\\s)";
        }


        // If we have evidence, try to extract a pattern from it — but require sufficient specificity
        if (!evidence.isEmpty() && evidence.length() >= 20 && evidence.length() < 200) {
            String escaped = Pattern.quote(evidence.trim());
            return "(?i)" + escaped;
        }

        return null;
    }

    /**
     */
    private boolean isPatternTooBroad(String pattern) {
        if (pattern == null) return true;
        // Reject patterns that are just (?i) + a few characters
        String withoutFlags = pattern.replaceAll("\\(\\?[imsx]+\\)", "");
        if (withoutFlags.length() < 15) return true;
        // Reject patterns that are just matching generic words
        if (withoutFlags.matches("(?i)\\(.*?(id|user|account|token|session|password|error|fail).*?\\)")) {
            // Only reject if the pattern is JUST these words without specific context
            if (!withoutFlags.contains("sql") && !withoutFlags.contains("script")
                    && !withoutFlags.contains("alert") && !withoutFlags.contains("etc/passwd")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if we already have a rule with similar type and pattern.
     */
    private boolean isDuplicateRule(String vulnType, String pattern) {
        for (LearnedRule existing : rules) {
            if (existing.getVulnType() != null && existing.getVulnType().equalsIgnoreCase(vulnType)
                    && existing.getPattern().equals(pattern)) {
                return true;
            }
        }
        return false;
    }

    private void compilePatterns() {
        compiledPatterns.clear();
        for (LearnedRule rule : rules) {
            compilePattern(rule);
        }
    }

    private void compilePattern(LearnedRule rule) {
        try {
            Pattern p = Pattern.compile(rule.getPattern(), Pattern.CASE_INSENSITIVE);
            compiledPatterns.put(rule.getPattern(), p);
        } catch (PatternSyntaxException e) {
            logger.warn("[规则学习] 无效正则: %s - %s", rule.getPattern(), e.getMessage());
        }
    }

    /**
     * Get all learned rules (for display in UI).
     */
    public List<LearnedRule> getRules() {
        return new ArrayList<>(rules);
    }

    /**
     * Remove a rule by index.
     */
    public void removeRule(int index) {
        if (index >= 0 && index < rules.size()) {
            LearnedRule removed = rules.remove(index);
            compiledPatterns.remove(removed.getPattern());
            saveRules();
        }
    }

    /**
     * Get rule count.
     */
    public int getRuleCount() {
        return rules.size();
    }

    public void shutdown() {
        flushIfDirty();
        flushScheduler.shutdownNow();
        try {
            flushScheduler.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
