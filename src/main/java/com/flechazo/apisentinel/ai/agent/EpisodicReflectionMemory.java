package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Episodic Reflection Memory — inspired by Reflexion (NeurIPS 2023).
 *
 * <p>When a batch of payloads or tool calls fails to produce useful results,
 * this module generates a structured <em>verbal reflection</em> — a concise
 * natural-language analysis of what went wrong and what to do differently.
 * These reflections are stored in a sliding-window buffer and injected into
 * the LLM context before each subsequent call.
 *
 * <p>Key insight from Reflexion paper: agents that reflect on failures
 * improve from 80% → 91% on HumanEval <em>without any weight updates</em>,
 * purely by accumulating verbal lessons in context.
 *
 * <p>Integration in AgentLoop:
 * <pre>
 * // After a batch of send_request calls all return normal responses:
 * if (batchAllNormal) {
 *     messages.add(ChatMessage.user("【反思】" + r.diagnosis()));
 * }
 * // Before each LLM call:
 * if (!reflectionMemory.isEmpty()) {
 *     messages.add(ChatMessage.system(reflectionMemory.buildReflectionPrompt()));
 * }
 * </pre>
 */
public class EpisodicReflectionMemory {

    /** Maximum reflections kept in the sliding window. */
    private static final int MAX_REFLECTIONS = 8;

    /**
     * A single reflection — LLM-generated failure diagnosis + correction strategy.
     *
     * @param episode    which failure triggered this reflection (1-based count)
     * @param category   failure category tag for grouping
     * @param diagnosis  concise explanation of why the attempt failed
     * @param strategy   specific corrective action for the next attempt
     */
    public record Reflection(
            int episode,
            String category,
            String diagnosis,
            String strategy
    ) {}

    private final List<Reflection> reflections = new ArrayList<>();
    private final LeveledLogger logger;
    private int episodeCount = 0;
    /** Fast model name for cheap reflection-generation LLM calls. */
    private String fastModelName;

    public EpisodicReflectionMemory(LeveledLogger logger) {
        this.logger = logger;
    }

    /** Set the fast model name for cheap reflection-generation LLM calls. */
    public void setFastModelName(String name) {
        this.fastModelName = name;
    }

    /**
    /**
     * Manually add a reflection (e.g., from error compression).
     */
    public void addReflectionDirect(String category, String diagnosis, String strategy) {
        episodeCount++;
        addReflection(new Reflection(episodeCount, category, diagnosis, strategy));
    }

    /**
     * Build the reflection prompt to inject before each LLM call.
     * Returns empty string if no reflections exist.
     */
    public String buildReflectionPrompt() {
        if (reflections.isEmpty()) return "";

        StringBuilder sb = new StringBuilder(
                "【历史教训 — 避免重复错误（Reflexion 记忆）】\n");
        for (int i = 0; i < reflections.size(); i++) {
            Reflection r = reflections.get(i);
            sb.append(String.format("%d. [%s] %s → 策略: %s\n",
                    i + 1, r.category(), r.diagnosis(), r.strategy()));
        }
        sb.append("\n请在生成新 payload 或选择新工具时参考以上教训。\n");
        return sb.toString();
    }

    /**
     * Whether there are any stored reflections.
     */
    public boolean isEmpty() {
        return reflections.isEmpty();
    }

    /**
     * Get all stored reflections (read-only).
     */
    public List<Reflection> getReflections() {
        return Collections.unmodifiableList(reflections);
    }

    /**
     * Get the current episode count.
     */
    public int getEpisodeCount() {
        return episodeCount;
    }

    /**
     * Clear all reflections (for testing or reset).
     */
    public void clear() {
        reflections.clear();
        episodeCount = 0;
    }

    // ── Internal ──

    private void addReflection(Reflection r) {
        reflections.add(r);
        // Sliding window: remove oldest when exceeding max
        while (reflections.size() > MAX_REFLECTIONS) {
            reflections.remove(0);
        }
    }

    private Reflection parseReflection(String json) {
        try {
            // P1-1: route through JsonExtractor, which already handles
            // markdown code-fence stripping, bracket-counting, and
            // other LLM-output quirks — the pre-P1-1 inline regex
            // missed cases where the model wrapped the JSON in prose
            // ("Here is the reflection:\n{...}") or emitted trailing
            // commas that strict JsonParser rejects.
            var obj = com.flechazo.apisentinel.util.JsonExtractor.extract(json);
            if (obj == null) return null;
            String category = obj.has("category") ? obj.get("category").getAsString() : "other";
            String diagnosis = obj.has("diagnosis") ? obj.get("diagnosis").getAsString() : "";
            String strategy = obj.has("strategy") ? obj.get("strategy").getAsString() : "";

            if (diagnosis.isEmpty()) return null;

            return new Reflection(episodeCount, category, diagnosis, strategy);
        } catch (Exception e) {
            // Fallback: try to extract key fields with regex
            String category = extractField(json, "category", "other");
            String diagnosis = extractField(json, "diagnosis", "");
            String strategy = extractField(json, "strategy", "");
            if (diagnosis.isEmpty()) return null;
            return new Reflection(episodeCount, category, diagnosis, strategy);
        }
    }

    private String extractField(String json, String field, String defaultValue) {
        // Simple regex extraction for when JSON parsing fails
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "\"" + field + "\"\\s*:\\s*\"([^\"]*)\"");
        var m = p.matcher(json);
        return m.find() ? m.group(1) : defaultValue;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
