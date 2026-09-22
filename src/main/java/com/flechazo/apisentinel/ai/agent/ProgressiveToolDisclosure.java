package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.tool.AgentTool;
import com.flechazo.apisentinel.ai.agent.tool.AgentToolRegistry;
import com.flechazo.apisentinel.ai.provider.ToolDefinition;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Progressive Tool Disclosure — only expose tools relevant to the current analysis phase.
 *
 * <p>Based on Anthropic's MCP Tool Tax research: tool schemas consume a significant
 * share of prompt tokens in a typical deployment. With 41 tools, the full tool catalog
 * consumes ~7.9K tokens per turn.
 *
 * <p>This class groups tools into phases and provides phase-aware filtering:
 * <ul>
 *   <li><b>CORE</b> — always available (4 tools)</li>
 *   <li><b>RECON</b> — reconnaissance and code analysis tools</li>
 *   <li><b>PAYLOAD_TESTING</b> — payload generation and verification tools</li>
 *   <li><b>BROWSER</b> — browser-based testing tools</li>
 *   <li><b>ADVANCED</b> — probes, OOB, sandboxed code</li>
 *   <li><b>CHAIN</b> — cluster hunting and sibling exploration</li>
 *   <li><b>META</b> — user interaction, analysis notes, traffic analysis, and
 *       the {@code request_tools} meta-tool for on-demand group loading</li>
 * </ul>
 *
 * <p>The agent can also request additional tool groups on demand via the
 * {@code request_tools} meta-tool.
 *
 * <p>Expected token savings: up to ~57% reduction in tool schema tokens per turn
 * when only RECON+CORE+META are active (e.g. early iterations).
 */
public class ProgressiveToolDisclosure {

    /** Analysis phases. */
    public enum Phase {
        RECON("侦察阶段"),
        PAYLOAD_TESTING("Payload 测试阶段"),
        BROWSER("浏览器测试阶段"),
        ADVANCED("高级探测阶段"),
        CHAIN("集群狩猎阶段"),
        META("元工具");

        private final String displayName;
        Phase(String displayName) { this.displayName = displayName; }
        public String displayName() { return displayName; }
    }

    /** Tools always available regardless of phase. */
    public static final Set<String> CORE_TOOLS = Set.of(
            "send_request",
            "read_file",
            "grep_repo",
            "submit_report"
    );

    /** Phase → tool name mappings. */
    public static final Map<Phase, Set<String>> PHASE_TOOLS;
    static {
        Map<Phase, Set<String>> m = new EnumMap<>(Phase.class);

        m.put(Phase.RECON, Set.of(
                "heuristic_scan", "fingerprint_components",
                "search_source_code", "audit_codebase",
                "find_definition", "find_callers",
                "search_traffic", "list_sessions",
                "trace_taint_source",
                "get_burp_scan_issues",
                "mine_history_idor",
                "list_attack_types", "scan_mcp_servers"));

        m.put(Phase.PAYLOAD_TESTING, Set.of(
                "generate_payloads", "test_auth_bypass",
                "verify_boolean_blind", "verify_timing_blind",
                "waf_bypass_retry", "verify_business_logic",
                "verify_xss_reflection", "verify_ssti",
                "verify_path_traversal", "verify_xxe",
                "diff_responses",
                "generate_poc", "custom_detection"));

        m.put(Phase.BROWSER, Set.of(
                "browser_login", "browser_discover", "browser_render",
                "browser_dom_xss", "browser_find_page",
                "browser_interact", "browser_explore", "browser_auto_crawl",
                "register_discovered_apis"));

        m.put(Phase.ADVANCED, Set.of(
                "active_probe", "generate_oob_probe", "check_oob_results",
                "run_sandboxed_code"));

        m.put(Phase.CHAIN, Set.of(
                "map_sibling_endpoints", "chain_hunter",
                "dispatch_explore_agent"));

        m.put(Phase.META, Set.of(
                "ask_user", "update_analysis_notes",
                "read_analysis_notes",
                "analyze_traffic", "request_tools",
                "orchestrate_agents"));

        PHASE_TOOLS = Collections.unmodifiableMap(m);
    }

    /** All known tool names across all phases (for validation). */
    public static final Set<String> ALL_PHASED_TOOLS;
    static {
        Set<String> all = new LinkedHashSet<>(CORE_TOOLS);
        PHASE_TOOLS.values().forEach(all::addAll);
        ALL_PHASED_TOOLS = Collections.unmodifiableSet(all);
    }

    private final LeveledLogger logger;

    /** Currently active phases (starts with RECON, expanded as analysis progresses). */
    private final Set<Phase> activePhases = EnumSet.of(Phase.RECON);

    /** Tool groups explicitly requested by the agent via request_tools. */
    private final Set<Phase> requestedPhases = EnumSet.noneOf(Phase.class);

    /** Last detected phase (for logging changes). */
    private Phase lastDetectedPhase = Phase.RECON;

    public ProgressiveToolDisclosure(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Detect the current analysis phase from tool call history.
     *
     * <p>Phase transitions:
     * <pre>
     * RECON → (heuristic_scan done + code analysis done) → PAYLOAD_TESTING
     * PAYLOAD_TESTING → (browser tool called) → BROWSER
     * PAYLOAD_TESTING → (chain_hunter/map_sibling called) → CHAIN
     * Any → (active_probe/generate_oob_probe called) → ADVANCED
     * </pre>
     */
    public Phase detectPhase(Set<String> calledTools, int iteration) {
        Phase detected;

        // If browser tools have been called, we're in browser phase
        if (calledTools.stream().anyMatch(t -> PHASE_TOOLS.get(Phase.BROWSER).contains(t))) {
            detected = Phase.BROWSER;
        }
        // If chain hunting tools called, we're in chain phase
        else if (calledTools.stream().anyMatch(t -> PHASE_TOOLS.get(Phase.CHAIN).contains(t))) {
            detected = Phase.CHAIN;
        }
        // If advanced tools called
        else if (calledTools.stream().anyMatch(t -> PHASE_TOOLS.get(Phase.ADVANCED).contains(t))) {
            detected = Phase.ADVANCED;
        }
        // If payload generation or verification started, we're in testing phase
        else if (calledTools.contains("generate_payloads")
                || calledTools.contains("test_auth_bypass")
                || calledTools.contains("verify_boolean_blind")
                || calledTools.contains("verify_timing_blind")) {
            detected = Phase.PAYLOAD_TESTING;
        }
        // Early iterations or still doing recon
        else {
            detected = Phase.RECON;
        }

        // Track phase changes
        if (detected != lastDetectedPhase) {
            logger.info("[ProgressiveToolDisclosure] 阶段转换: %s → %s (迭代 %d)",
                    lastDetectedPhase.displayName(), detected.displayName(), iteration);
            lastDetectedPhase = detected;
        }

        // Update active phases (phases are additive — once entered, stay active)
        activePhases.add(detected);

        return detected;
    }

    /**
     * Get tool definitions filtered for the current phase.
     *
     * <p>Returns: CORE tools + current phase tools + any explicitly requested phase tools.
     * Tools not registered in the full registry are silently skipped.
     *
     * @param currentPhase the detected analysis phase
     * @param fullRegistry the complete tool registry with all 43 tools
     * @return filtered list of tool definitions
     */
    public List<ToolDefinition> getToolsForPhase(Phase currentPhase, AgentToolRegistry fullRegistry) {
        Set<String> activeToolNames = new LinkedHashSet<>(CORE_TOOLS);

        // Add tools for all active phases
        for (Phase phase : activePhases) {
            Set<String> phaseTools = PHASE_TOOLS.get(phase);
            if (phaseTools != null) {
                activeToolNames.addAll(phaseTools);
            }
        }

        // Add explicitly requested phases
        for (Phase phase : requestedPhases) {
            Set<String> phaseTools = PHASE_TOOLS.get(phase);
            if (phaseTools != null) {
                activeToolNames.addAll(phaseTools);
            }
        }

        // Always include META tools (low token cost, high utility)
        Set<String> metaTools = PHASE_TOOLS.get(Phase.META);
        if (metaTools != null) {
            activeToolNames.addAll(metaTools);
        }

        // Filter from the full registry
        List<ToolDefinition> filtered = activeToolNames.stream()
                .filter(fullRegistry::hasTool)
                .map(name -> fullRegistry.getTool(name).toDefinition())
                .toList();

        logger.debug("[ProgressiveToolDisclosure] 暴露 %d/%d 个工具 (阶段: %s)",
                filtered.size(), countAllTools(fullRegistry), currentPhase.displayName());

        return filtered;
    }

    /**
     * Request loading of an additional tool group.
     * Called by the request_tools meta-tool when the agent needs more capabilities.
     *
     * @param groupName the phase group name (e.g. "payload_testing", "browser", "advanced")
     * @return true if the group was found and activated
     */
    public boolean requestToolGroup(String groupName) {
        String normalized = groupName.trim().toUpperCase().replace(" ", "_");
        try {
            Phase phase = Phase.valueOf(normalized);
            requestedPhases.add(phase);
            activePhases.add(phase);
            logger.info("[ProgressiveToolDisclosure] Agent 请求加载工具组: %s", phase.displayName());
            return true;
        } catch (IllegalArgumentException e) {
            logger.warn("[ProgressiveToolDisclosure] 未知工具组: %s", groupName);
            return false;
        }
    }

    /**
     * Get a description of available tool groups for the request_tools meta-tool.
     */
    public String getAvailableGroupsDescription() {
        StringBuilder sb = new StringBuilder();
        for (Phase phase : Phase.values()) {
            if (phase == Phase.META) continue;
            boolean active = activePhases.contains(phase) || requestedPhases.contains(phase);
            sb.append(String.format("- %s (%s): %s\n",
                    phase.name().toLowerCase(),
                    phase.displayName(),
                    active ? "✓ 已加载" : "未加载"));
        }
        return sb.toString();
    }

    /**
     * Get the set of currently active phases.
     */
    public Set<Phase> getActivePhases() {
        return Collections.unmodifiableSet(activePhases);
    }

    /**
     * Validate that every name in {@code ALL_PHASED_TOOLS} is registered in the
     * runtime registry, and vice-versa. Returns a human-readable summary of any
     * drift so the caller can log/warn at startup; an empty string means the
     * two sets are in perfect sync.
     *
     * <p>Catches the two failure modes that caused four tools to be silently
     * unreachable (e.g. {@code "response_diff"} vs the registered
     * {@code "diff_responses"}, {@code "ssrf_oob"} vs {@code "generate_oob_probe"}),
     * and tools that exist in the registry but never enter any phase (so they'd
     * never be exposed by {@link #getToolsForPhase}).
     */
    public static String validateConsistency(java.util.Set<String> registryNames) {
        java.util.Set<String> missingFromRegistry = new java.util.LinkedHashSet<>();
        for (String name : ALL_PHASED_TOOLS) {
            if (!registryNames.contains(name)) missingFromRegistry.add(name);
        }
        java.util.Set<String> unphased = new java.util.LinkedHashSet<>();
        for (String name : registryNames) {
            if (!ALL_PHASED_TOOLS.contains(name)) unphased.add(name);
        }
        if (missingFromRegistry.isEmpty() && unphased.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        if (!missingFromRegistry.isEmpty()) {
            sb.append("[ProgressiveToolDisclosure] ").append(missingFromRegistry.size())
              .append(" tool(s) listed in PHASE_TOOLS but not registered: ")
              .append(missingFromRegistry).append(". ");
        }
        if (!unphased.isEmpty()) {
            sb.append("[ProgressiveToolDisclosure] ").append(unphased.size())
              .append(" registered tool(s) not in any phase: ")
              .append(unphased);
        }
        return sb.toString();
    }

    /**
     * Estimate token savings from progressive disclosure.
     *
     * @param fullRegistry the complete registry
     * @return approximate percentage of tokens saved per turn
     */
    public int estimateTokenSavingsPercent(AgentToolRegistry fullRegistry) {
        int totalTools = countAllTools(fullRegistry);
        int activeTools = CORE_TOOLS.size() + PHASE_TOOLS.get(lastDetectedPhase).size()
                + PHASE_TOOLS.get(Phase.META).size();
        if (totalTools == 0) return 0;
        return (int) ((1.0 - (double) activeTools / totalTools) * 100);
    }

    private int countAllTools(AgentToolRegistry registry) {
        return registry.getDefinitions().size();
    }
}
