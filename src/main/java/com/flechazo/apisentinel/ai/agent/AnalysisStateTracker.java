package com.flechazo.apisentinel.ai.agent;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Structured tracker for the Agent's analysis progress across vulnerability categories.
 *
 * <p>Replaces the current approach where the LLM must "remember" what it tested
 * across 50+ iterations. This tracker is updated programmatically after each
 * tool execution and injected into messages at reflection checkpoints, giving
 * the model an accurate, loss-free view of coverage.
 *
 * <p>Usage in AgentLoop:
 * <pre>
 *   // After send_request returns:
 *   stateTracker.recordTest("SQLi", "query.id", evidence);
 *   // At iteration 15 reflection:
 *   messages.add(ChatMessage.user(stateTracker.buildStatusSnapshot()));
 * </pre>
 */
public class AnalysisStateTracker {

    /** Vulnerability categories the Agent should consider. */
    public enum VulnCategory {
        SQL_INJECTION("SQL注入"),
        XSS("XSS"),
        SSRF("SSRF"),
        IDOR("越权/IDOR"),
        PATH_TRAVERSAL("路径穿越"),
        COMMAND_INJECTION("命令注入"),
        DESERIALIZATION("反序列化"),
        XXE("XXE"),
        SSTI("SSTI模板注入"),
        AUTH_BYPASS("认证绕过"),
        BUSINESS_LOGIC("业务逻辑"),
        INFO_DISCLOSURE("信息泄露"),
        CSRF("CSRF"),
        OPEN_REDIRECT("开放重定向"),
        FILE_UPLOAD("文件上传漏洞");

        private final String displayName;
        VulnCategory(String displayName) { this.displayName = displayName; }
        public String displayName() { return displayName; }
    }

    /** Status of a vulnerability category. */
    public enum CategoryStatus {
        UNTESTED("未测试"),
        IN_PROGRESS("测试中"),
        CONFIRMED_VULNERABLE("已确认漏洞"),
        SUSPECTED("疑似"),
        CONFIRMED_SAFE("确认安全"),
        NOT_APPLICABLE("不适用");

        private final String displayName;
        CategoryStatus(String displayName) { this.displayName = displayName; }
        public String displayName() { return displayName; }
    }

    /** Evidence for a specific test. */
    public record Evidence(
            String tool,        // tool that produced this evidence
            String parameter,   // parameter tested
            String summary,     // one-line result summary
            boolean anomalous   // whether the response was anomalous
    ) {}

    // Category → status
    private final Map<VulnCategory, CategoryStatus> categories = new ConcurrentHashMap<>();
    // Category → list of evidence
    private final Map<VulnCategory, List<Evidence>> evidenceMap = new ConcurrentHashMap<>();
    // Applicable categories for this specific API (set by profile)
    private final Set<VulnCategory> applicableCategories = EnumSet.noneOf(VulnCategory.class);
    // Analysis profile name
    private String profileName = "通用";
    // Total payloads sent
    private int totalPayloadsSent = 0;
    // Total anomalous responses
    private int totalAnomalies = 0;

    public AnalysisStateTracker() {
        // Initialize all categories as UNTESTED
        for (VulnCategory cat : VulnCategory.values()) {
            categories.put(cat, CategoryStatus.UNTESTED);
        }
    }

    /**
     * Set which categories are applicable for this API (from analysis profile).
     */
    public void setApplicableCategories(Set<VulnCategory> applicable) {
        applicableCategories.clear();
        applicableCategories.addAll(applicable);
        // Mark non-applicable categories
        for (VulnCategory cat : VulnCategory.values()) {
            if (!applicable.contains(cat)) {
                categories.put(cat, CategoryStatus.NOT_APPLICABLE);
            }
        }
    }

    public void setProfileName(String name) {
        this.profileName = name;
    }

    /**
     * Record a test result for a vulnerability category.
     */
    public void recordTest(VulnCategory category, String parameter,
                           String tool, String summary, boolean anomalous) {
        categories.put(category, anomalous ? CategoryStatus.IN_PROGRESS : CategoryStatus.IN_PROGRESS);
        evidenceMap.computeIfAbsent(category, k -> new ArrayList<>())
                .add(new Evidence(tool, parameter, summary, anomalous));
        totalPayloadsSent++;
        if (anomalous) totalAnomalies++;
    }

    /**
     * Convenience: record from send_request result string.
     */
    public void recordFromSendRequest(String parameter, String result) {
        boolean anomalous = result != null && (
                result.contains("\"anomaly\":true")
                || result.contains("SQL 错误") || result.contains("sql error")
                || result.contains("堆栈跟踪") || result.contains("stack trace")
                || result.contains("异常") || result.contains("error"));
        boolean wafBlocked = result != null && (
                result.contains("waf_detected") || result.contains("\"waf_detected\":true"));

        String summary = wafBlocked ? "WAF拦截"
                : anomalous ? "异常响应" : "正常响应";

        // Infer category from parameter context (best-effort)
        VulnCategory cat = inferCategory(parameter);
        recordTest(cat, parameter, "send_request", summary, anomalous && !wafBlocked);
    }

    /**
     * Mark a category with a final status.
     */
    public void markCategory(VulnCategory category, CategoryStatus status) {
        categories.put(category, status);
    }

    /**
     * Build a status snapshot for injection into messages.
     * Called at reflection checkpoints (iteration 15, 30, etc.)
     */
    public String buildStatusSnapshot() {
        StringBuilder sb = new StringBuilder();
        sb.append("【分析状态追踪】Profile: ").append(profileName).append("\n");
        sb.append("已发送 ").append(totalPayloadsSent).append(" 个 payload，")
                .append(totalAnomalies).append(" 个异常响应\n\n");

        // Group by status
        Map<CategoryStatus, List<VulnCategory>> grouped = new LinkedHashMap<>();
        for (var entry : categories.entrySet()) {
            grouped.computeIfAbsent(entry.getValue(), k -> new ArrayList<>()).add(entry.getKey());
        }

        // Show tested/testable categories first
        for (CategoryStatus status : new CategoryStatus[]{
                CategoryStatus.CONFIRMED_VULNERABLE, CategoryStatus.SUSPECTED,
                CategoryStatus.IN_PROGRESS, CategoryStatus.CONFIRMED_SAFE,
                CategoryStatus.UNTESTED}) {
            List<VulnCategory> cats = grouped.get(status);
            if (cats == null || cats.isEmpty()) continue;

            sb.append("**").append(status.displayName()).append("** (").append(cats.size()).append("): ");
            for (int i = 0; i < cats.size(); i++) {
                VulnCategory cat = cats.get(i);
                sb.append(cat.displayName());
                List<Evidence> ev = evidenceMap.get(cat);
                if (ev != null && !ev.isEmpty()) {
                    sb.append("[").append(ev.size()).append("个证据]");
                }
                if (i < cats.size() - 1) sb.append(", ");
            }
            sb.append("\n");
        }

        // Coverage calculation
        long tested = categories.values().stream()
                .filter(s -> s != CategoryStatus.UNTESTED && s != CategoryStatus.NOT_APPLICABLE)
                .count();
        long applicable = applicableCategories.isEmpty()
                ? categories.values().stream().filter(s -> s != CategoryStatus.NOT_APPLICABLE).count()
                : applicableCategories.size();
        long untested = applicable - tested;

        sb.append("\n**覆盖率**: ").append(tested).append("/").append(applicable)
                .append(" 个适用类别已测试");
        if (untested > 0) {
            sb.append("，仍有 ").append(untested).append(" 个未覆盖");
        }
        sb.append("\n");

        return sb.toString();
    }

    /**
     * Build a pre-submit coverage check message.
     * Returns null if coverage is sufficient, otherwise returns a warning.
     */
    public String buildCoverageCheck() {
        long applicable = applicableCategories.isEmpty()
                ? categories.entrySet().stream()
                    .filter(e -> e.getValue() != CategoryStatus.NOT_APPLICABLE)
                    .count()
                : applicableCategories.size();
        long untested = categories.entrySet().stream()
                .filter(e -> e.getValue() == CategoryStatus.UNTESTED
                        && (applicableCategories.isEmpty() || applicableCategories.contains(e.getKey())))
                .count();

        if (untested == 0) return null;

        List<String> untestedNames = new ArrayList<>();
        for (var entry : categories.entrySet()) {
            if (entry.getValue() == CategoryStatus.UNTESTED
                    && (applicableCategories.isEmpty() || applicableCategories.contains(entry.getKey()))) {
                untestedNames.add(entry.getKey().displayName());
            }
        }

        return "【提交前覆盖率检查】\n"
                + "仍有 " + untested + "/" + applicable + " 个适用漏洞类别未测试: "
                + String.join(", ", untestedNames) + "\n"
                + "建议至少快速检查这些类别后再提交，或在报告中说明跳过原因。";
    }

    /**
     * Get current status of a category.
     */
    public CategoryStatus getStatus(VulnCategory category) {
        return categories.getOrDefault(category, CategoryStatus.UNTESTED);
    }

    /**
     * Get all evidence for a category.
     */
    public List<Evidence> getEvidence(VulnCategory category) {
        return evidenceMap.getOrDefault(category, List.of());
    }

    public int getTotalPayloadsSent() { return totalPayloadsSent; }
    public int getTotalAnomalies() { return totalAnomalies; }

    /**
     * Infer vulnerability category from parameter name/context (best-effort).
     */
    private VulnCategory inferCategory(String parameter) {
        if (parameter == null) return VulnCategory.SQL_INJECTION; // default
        String p = parameter.toLowerCase();
        if (p.contains("url") || p.contains("redirect") || p.contains("link") || p.contains("href"))
            return VulnCategory.SSRF;
        if (p.contains("file") || p.contains("path") || p.contains("dir") || p.contains("upload"))
            return VulnCategory.PATH_TRAVERSAL;
        if (p.contains("cmd") || p.contains("exec") || p.contains("command") || p.contains("shell"))
            return VulnCategory.COMMAND_INJECTION;
        if (p.contains("template") || p.contains("render") || p.contains("expression"))
            return VulnCategory.SSTI;
        if (p.contains("xml") || p.contains("entity") || p.contains("dtd"))
            return VulnCategory.XXE;
        if (p.contains("script") || p.contains("html") || p.contains("content") || p.contains("body"))
            return VulnCategory.XSS;
        if (p.contains("role") || p.contains("admin") || p.contains("permission") || p.contains("auth"))
            return VulnCategory.AUTH_BYPASS;
        if (p.contains("price") || p.contains("amount") || p.contains("quantity") || p.contains("coupon"))
            return VulnCategory.BUSINESS_LOGIC;
        if (p.contains("id") || p.contains("user") || p.contains("account") || p.contains("owner"))
            return VulnCategory.IDOR;
        return VulnCategory.SQL_INJECTION; // default assumption for unknown params
    }
}
