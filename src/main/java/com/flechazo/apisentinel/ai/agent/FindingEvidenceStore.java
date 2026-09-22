package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Finding Evidence Store — persistent storage for security findings that survives
 * context compaction. Inspired by MemGPT's three-tier memory and CrewAI's Entity Memory.
 *
 * <p>Problem: the current AgentLoop compacts old tool results (keeping only 15 recent),
 * causing early findings to "disappear" from the LLM's context. A SQL injection discovered
 * in iteration 5 may be forgotten by iteration 30.
 *
 * <p>Solution: maintain a structured, always-accessible store of findings that gets
 * injected into messages before each LLM call. The store supports both:
 * <ul>
 *   <li><b>Automatic ingestion</b> — findings extracted from tool results after each call</li>
 *   <li><b>Manual management</b> — agent can call {@code update_analysis_notes} to add/update findings</li>
 * </ul>
 *
 * <p>The store is organized by confidence level and vulnerability category,
 * producing a compact summary (~2000 chars max) for context injection.
 */
public class FindingEvidenceStore {

    /** Confidence levels for findings. */
    public enum ConfidenceLevel {
        CONFIRMED("已确认"),
        SUSPECTED("疑似"),
        NEGATIVE("排除"),
        NOTE("备注");

        private final String displayName;
        ConfidenceLevel(String displayName) { this.displayName = displayName; }
        public String displayName() { return displayName; }
    }

    /** Vulnerability categories (aligned with AnalysisStateTracker.VulnCategory). */
    public enum FindingCategory {
        SQL_INJECTION("SQL注入"),
        XSS("XSS"),
        SSRF("SSRF"),
        IDOR("越权/IDOR"),
        PATH_TRAVERSAL("路径穿越"),
        COMMAND_INJECTION("命令注入"),
        DESERIALIZATION("反序列化"),
        XXE("XXE"),
        SSTI("模板注入"),
        AUTH_BYPASS("认证绕过"),
        BUSINESS_LOGIC("业务逻辑"),
        INFO_DISCLOSURE("信息泄露"),
        CSRF("CSRF"),
        OPEN_REDIRECT("开放重定向"),
        FILE_UPLOAD("文件上传"),
        OTHER("其他");

        private final String displayName;
        FindingCategory(String displayName) { this.displayName = displayName; }
        public String displayName() { return displayName; }
    }

    /**
     * A single finding with evidence.
     *
     * @param id            unique ID ("F001", "F002"...)
     * @param iteration     iteration when discovered (-1 if manual)
     * @param category      vulnerability category
     * @param parameter     the parameter or endpoint involved
     * @param evidence      concise evidence summary (payload + response特征)
     * @param level         confidence level
     * @param sourceTool    which tool discovered it ("send_request", "agent_manual", etc.)
     * @param timestamp     when it was created
     */
    public record Finding(
            String id,
            int iteration,
            FindingCategory category,
            String parameter,
            String evidence,
            ConfidenceLevel level,
            String sourceTool,
            long timestamp
    ) {}

    /** A free-text progress note — the agent's running narrative (已测端点 /
     *  当前 hypothesis / 卡点 / 失败 payload / 做到哪步). Unlike the structured
     *  {@link Finding} entries, this carries the reasoning/state context that
     *  doesn't fit a category+evidence shape. Tagged with the context-window id
     *  it was written in so a new window can recover only what it's missing.
     *
     *  <p>Survives both context compaction and context-window rollover — it is
     *  the handoff payload the prior window writes before history is cleared. */
    public record ProgressNote(String text, long timestamp, int windowId) {}

    private final Map<String, Finding> findings = new ConcurrentHashMap<>();
    private final List<ProgressNote> progressNotes = new CopyOnWriteArrayList<>();
    /** Current context-window id (0 in the first/only window). Set by AgentLoop
     *  when it rolls over, so progress notes are tagged with the window they
     *  were written in and a new window can recover only what it's missing. */
    private volatile int currentWindowId = 0;
    private final LeveledLogger logger;
    /** Thread-safe ID generator — {@link AtomicInteger} prevents ID collisions
     *  when findings are added concurrently from the agent loop thread and
     *  tool execution threads. */
    private final AtomicInteger nextId = new AtomicInteger(1);

    /** Maximum length for the findings summary injection. */
    private static final int MAX_SUMMARY_LENGTH = 2000;
    public FindingEvidenceStore(LeveledLogger logger) {
        this.logger = logger;
    }

    // ========== Automatic Ingestion ==========

    /**
     * Automatically extract findings from a tool result.
     * Called after each tool execution in AgentLoop.
     *
     * @param toolName  the tool that produced this result
     * @param result    the raw tool result string
     * @param iteration current iteration number
     */
    public void ingestFromToolResult(String toolName, String result, int iteration) {
        if (result == null || result.isEmpty()) return;

        switch (toolName) {
            case "send_request" -> ingestFromSendRequest(result, iteration);
            case "heuristic_scan" -> ingestFromHeuristicScan(result, iteration);
            case "audit_codebase" -> ingestFromAuditCodebase(result, iteration);
            case "verify_boolean_blind", "verify_timing_blind" ->
                    ingestFromBlindVerification(result, iteration, toolName);
            case "test_auth_bypass" -> ingestFromAuthBypass(result, iteration);
            default -> { /* other tools don't produce findings directly */ }
        }
    }

    // ========== Manual Management (Agent Self-Managed Memory) ==========

    /**
     * Add a finding manually — called by the update_analysis_notes tool.
     * This implements MemGPT-style agent self-management of memory.
     *
     * @param category  vulnerability category string
     * @param parameter parameter or endpoint
     * @param evidence  evidence description
     * @param level     confidence level string
     * @return the created finding's ID
     */
    public String addManualFinding(String category, String parameter,
                                    String evidence, String level) {
        FindingCategory cat = parseCategory(category);
        ConfidenceLevel lvl = parseLevel(level);

        String id = String.format("F%03d", nextId.getAndIncrement());
        Finding finding = new Finding(id, -1, cat, parameter, evidence, lvl,
                "agent_manual", System.currentTimeMillis());
        findings.put(id, finding);

        logger.info("[FindingStore] 手动添加发现: %s [%s] %s — %s",
                id, lvl.displayName(), cat.displayName(), truncate(evidence, 80));
        return id;
    }

    /**
     * Update an existing finding's confidence level.
     *
     * @param findingId the finding ID to update
     * @param newLevel  new confidence level string
     * @return true if the finding was found and updated
     */
    public boolean updateFindingLevel(String findingId, String newLevel) {
        Finding existing = findings.get(findingId);
        if (existing == null) return false;

        ConfidenceLevel lvl = parseLevel(newLevel);
        findings.put(findingId, new Finding(
                existing.id(), existing.iteration(), existing.category(),
                existing.parameter(), existing.evidence(), lvl,
                existing.sourceTool(), existing.timestamp()));

        logger.info("[FindingStore] 更新 %s 级别: → %s", findingId, lvl.displayName());
        return true;
    }

    // ========== Free-text Progress Notes ==========

    /** Set the current context-window id. Called by AgentLoop on rollover; the
     *  next {@link #appendProgress(String)} tags its notes with this id. */
    public void setCurrentWindowId(int windowId) {
        this.currentWindowId = windowId;
    }

    public int getCurrentWindowId() {
        return currentWindowId;
    }

    /** Append a free-text progress note tagged with the current context-window id.
     *  Called by {@code update_analysis_notes(action=progress)} so the agent can
     *  hand its running narrative (已测端点 / 当前 hypothesis / 卡点 / 失败 payload)
     *  to the next window before a rollover clears the conversation. */
    public void appendProgress(String text) {
        appendProgress(text, currentWindowId);
    }

    /** Explicit-window overload — for checkpoints or tests that want to pin
     *  the window id regardless of the store's current setting. */
    public void appendProgress(String text, int windowId) {
        if (text == null || text.isBlank()) return;
        progressNotes.add(new ProgressNote(text.strip(), System.currentTimeMillis(), windowId));
        logger.debug("[FindingStore] progress 记录 (window %d): %s",
                windowId, truncate(text, 80));
    }

    /** Progress notes recorded in a window <em>after</em> {@code sinceWindow} —
     *  what a new window needs to recover the prior narrative. Returns them in
     *  write order. */
    public List<ProgressNote> listProgress(int sinceWindow) {
        return progressNotes.stream()
                .filter(p -> p.windowId() > sinceWindow)
                .toList();
    }

    /** All progress notes, in write order (for {@code read_analysis_notes} with
     *  no window filter). */
    public List<ProgressNote> allProgress() {
        return List.copyOf(progressNotes);
    }

    /** Clear every progress note (management UI reset). */
    public void clearProgress() {
        progressNotes.clear();
    }

    // ========== Summary Generation ==========

    /**
     * Build a compact findings summary for injection into messages.
     * Capped at {@link #MAX_SUMMARY_LENGTH} characters.
     *
     * @return formatted summary string, or empty string if no findings
     */
    public String buildFindingsSummary() {
        if (findings.isEmpty()) return "";

        StringBuilder sb = new StringBuilder(
                "【已知发现（持久化存储，不因上下文压缩丢失）】\n");

        // Group by confidence level
        for (ConfidenceLevel level : ConfidenceLevel.values()) {
            List<Finding> group = findings.values().stream()
                    .filter(f -> f.level() == level)
                    .toList();
            if (group.isEmpty()) continue;

            sb.append("**").append(level.displayName())
                    .append("** (").append(group.size()).append("):\n");
            for (Finding f : group) {
                sb.append(String.format("  - [%s] %s @ %s: %s\n",
                        f.id(), f.category().displayName(),
                        f.parameter(), truncate(f.evidence(), 100)));
            }
        }

        sb.append(String.format("\n共 %d 个发现。使用 update_analysis_notes 工具添加/更新发现。\n",
                findings.size()));

        // Enforce max length
        String result = sb.toString();
        if (result.length() > MAX_SUMMARY_LENGTH) {
            result = result.substring(0, MAX_SUMMARY_LENGTH) + "\n...(已截断)";
        }
        return result;
    }

    /**
     * Get all findings (read-only).
     */
    public List<Finding> getAllFindings() {
        return List.copyOf(findings.values());
    }

    /**
     * Get findings by confidence level.
     */
    public List<Finding> getFindingsByLevel(ConfidenceLevel level) {
        return findings.values().stream()
                .filter(f -> f.level() == level)
                .toList();
    }

    /**
     * Get the total finding count.
     */
    public int size() {
        return findings.size();
    }

    /**
     * Whether there are any confirmed findings.
     */
    public boolean hasConfirmed() {
        return findings.values().stream().anyMatch(f -> f.level() == ConfidenceLevel.CONFIRMED);
    }

    // ========== Internal Ingestion Methods ==========

    /** P0-4 hardening: only ingest a finding when the tool reports a
     *  structured anomaly signal. The pre-P0-4 implementation also
     *  triggered on substring matches in the response body
     *  ("SQL 错误" / "stack trace" / "sql error") which gave an
     *  attacker who controls any response byte a way to pollute the
     *  evidence store: a honeypot endpoint that echoes those phrases
     *  in a normal 200 response would spawn a fake SUSPECTED finding,
     *  which survives context compaction (the store is the long-term
     *  memory) and re-enters the model's prompt as if it were an
     *  analyst-observed signal.
     *
     *  <p>Category is now fixed to {@link FindingCategory#OTHER} for
     *  auto-ingested send_request findings. The previous
     *  {@link #inferCategoryFromResult} classifier keyed off the same
     *  attacker-controllable body text ("sql" anywhere → SQL_INJECTION)
     *  and is no longer trusted for ingestion from this tool.
     *
     *  <p>This doesn't break legitimate anomaly ingestion:
     *  {@code SendRequestTool} writes {@code "anomaly":true} whenever
     *  the response diverges from the baseline, and that's the only
     *  signal we need. */
    private void ingestFromSendRequest(String result, int iteration) {
        if (!hasStructuredAnomaly(result)) return;

        String evidence = extractEvidenceSnippet(result);
        addFinding(iteration, FindingCategory.OTHER, "auto-detected", evidence,
                ConfidenceLevel.SUSPECTED, "send_request");
    }

    /** True when the tool result carries a programmatic anomaly flag —
     *  the {@code "anomaly":true} field that {@code SendRequestTool}
     *  emits on baseline-divergent responses. Substring matches on the
     *  response body are deliberately NOT consulted: those bytes are
     *  attacker-controlled and must not drive any part of the long-term
     *  memory. */
    private static boolean hasStructuredAnomaly(String result) {
        if (result == null) return false;
        // Match both Gson's compact form and pretty-printed form. The
        // boolean literal is the only substring we consult — any phrase
        // match ("SQL 错误" etc.) that the pre-P0-4 code used is gone.
        return result.contains("\"anomaly\":true") || result.contains("\"anomaly\": true");
    }

    private void ingestFromHeuristicScan(String result, int iteration) {
        if (result.contains("finding") || result.contains("发现")
                || result.contains("vulnerability") || result.contains("漏洞")) {
            String evidence = extractEvidenceSnippet(result);
            addFinding(iteration, FindingCategory.OTHER, "heuristic", evidence,
                    ConfidenceLevel.NOTE, "heuristic_scan");
        }
    }

    private void ingestFromAuditCodebase(String result, int iteration) {
        if (result.contains("SINK") || result.contains("sink")
                || result.contains("dangerous") || result.contains("危险")) {
            String evidence = extractEvidenceSnippet(result);
            FindingCategory cat = inferCategoryFromSink(result);
            addFinding(iteration, cat, "code-sink", evidence,
                    ConfidenceLevel.NOTE, "audit_codebase");
        }
    }

    private void ingestFromBlindVerification(String result, int iteration, String toolName) {
        boolean confirmed = result.contains("confirmed") || result.contains("确认")
                || result.contains("vulnerable");
        if (confirmed) {
            String evidence = extractEvidenceSnippet(result);
            addFinding(iteration, FindingCategory.SQL_INJECTION, "blind-verification",
                    evidence, ConfidenceLevel.CONFIRMED, toolName);
        }
    }

    private void ingestFromAuthBypass(String result, int iteration) {
        boolean bypassed = result.contains("bypass") || result.contains("绕过")
                || result.contains("unauthorized_access");
        if (bypassed) {
            String evidence = extractEvidenceSnippet(result);
            addFinding(iteration, FindingCategory.AUTH_BYPASS, "auth-test",
                    evidence, ConfidenceLevel.SUSPECTED, "test_auth_bypass");
        }
    }

    // ========== Helpers ==========

    private void addFinding(int iteration, FindingCategory category,
                             String parameter, String evidence,
                             ConfidenceLevel level, String sourceTool) {
        String id = String.format("F%03d", nextId.getAndIncrement());
        Finding finding = new Finding(id, iteration, category, parameter,
                evidence, level, sourceTool, System.currentTimeMillis());
        findings.put(id, finding);

        logger.debug("[FindingStore] 自动发现: %s [%s] %s (iter %d)",
                id, level.displayName(), category.displayName(), iteration);
    }

    private String extractEvidenceSnippet(String result) {
        // Extract the most relevant part of the result
        String snippet = result;
        // Remove JSON structure noise
        snippet = snippet.replaceAll("\"[a-z_]+\":", "");
        snippet = snippet.replaceAll("[{}\\[\\]]", "");
        snippet = snippet.strip();
        return truncate(snippet, 200);
    }

    private FindingCategory inferCategoryFromResult(String result) {
        String lower = result.toLowerCase();
        if (lower.contains("sql") || lower.contains("sqli")) return FindingCategory.SQL_INJECTION;
        if (lower.contains("xss") || lower.contains("script")) return FindingCategory.XSS;
        if (lower.contains("ssrf") || lower.contains("server-side")) return FindingCategory.SSRF;
        if (lower.contains("idor") || lower.contains("unauthorized")) return FindingCategory.IDOR;
        if (lower.contains("path") || lower.contains("traversal")) return FindingCategory.PATH_TRAVERSAL;
        if (lower.contains("command") || lower.contains("rce")) return FindingCategory.COMMAND_INJECTION;
        return FindingCategory.OTHER;
    }

    private FindingCategory inferCategoryFromSink(String result) {
        String lower = result.toLowerCase();
        if (lower.contains("sql") || lower.contains("query")) return FindingCategory.SQL_INJECTION;
        if (lower.contains("exec") || lower.contains("runtime")) return FindingCategory.COMMAND_INJECTION;
        if (lower.contains("deseriali") || lower.contains("readobject")) return FindingCategory.DESERIALIZATION;
        if (lower.contains("xxe") || lower.contains("xml")) return FindingCategory.XXE;
        if (lower.contains("template") || lower.contains("render")) return FindingCategory.SSTI;
        return FindingCategory.OTHER;
    }

    static FindingCategory parseCategory(String s) {
        if (s == null) return FindingCategory.OTHER;
        String upper = s.trim().toUpperCase().replace(" ", "_").replace("-", "_");
        try {
            return FindingCategory.valueOf(upper);
        } catch (IllegalArgumentException e) {
            // Try common aliases
            if (upper.contains("SQL")) return FindingCategory.SQL_INJECTION;
            if (upper.contains("AUTH")) return FindingCategory.AUTH_BYPASS;
            if (upper.contains("IDOR") || upper.contains("越权")) return FindingCategory.IDOR;
            return FindingCategory.OTHER;
        }
    }

    static ConfidenceLevel parseLevel(String s) {
        if (s == null) return ConfidenceLevel.NOTE;
        String upper = s.trim().toUpperCase().replace(" ", "_");
        try {
            return ConfidenceLevel.valueOf(upper);
        } catch (IllegalArgumentException e) {
            if (upper.contains("确认") || upper.contains("CONFIRM")) return ConfidenceLevel.CONFIRMED;
            if (upper.contains("疑似") || upper.contains("SUSPECT")) return ConfidenceLevel.SUSPECTED;
            if (upper.contains("排除") || upper.contains("NEGATIVE") || upper.contains("SAFE")) return ConfidenceLevel.NEGATIVE;
            return ConfidenceLevel.NOTE;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        s = s.strip();
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
