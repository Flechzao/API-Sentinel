package com.flechazo.apisentinel.mcp;

import com.flechazo.apisentinel.ai.agent.tool.AgentTool;
import com.flechazo.apisentinel.ai.agent.tool.BrowserDiscoverTool;
import com.flechazo.apisentinel.ai.agent.tool.BrowserDomXssTool;
import com.flechazo.apisentinel.ai.agent.tool.BrowserRenderTool;
import com.flechazo.apisentinel.ai.agent.tool.FindCallersTool;
import com.flechazo.apisentinel.ai.agent.tool.FindDefinitionTool;
import com.flechazo.apisentinel.ai.agent.tool.MapSiblingEndpointsTool;
import com.flechazo.apisentinel.ai.agent.tool.ReadFileTool;
import com.flechazo.apisentinel.ai.agent.tool.ToolContext;
import com.flechazo.apisentinel.ai.agent.tool.TraceTaintSourceTool;
import com.flechazo.apisentinel.ai.agent.tool.AgentToolRegistry;
import com.flechazo.apisentinel.ai.agent.tool.StandardToolRegistry;
import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore;
import com.flechazo.apisentinel.ai.agent.ProgressiveToolDisclosure;
import com.flechazo.apisentinel.ai.pipeline.AnalysisConfig;
import com.flechazo.apisentinel.ai.provider.ToolDefinition;
import com.flechazo.apisentinel.detection.OobService;
import com.flechazo.apisentinel.browser.BrowserService;
import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.ai.pipeline.PipelineResult;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;
import com.flechazo.apisentinel.ai.pipeline.VerdictValidator;
import com.flechazo.apisentinel.ai.pipeline.evidence.EvidenceField;
import com.flechazo.apisentinel.ai.pipeline.evidence.EvidenceSchema;
import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.codeindex.RepoGrepper;
import com.flechazo.apisentinel.codeindex.SinkAnnotator;
import com.flechazo.apisentinel.codeindex.SinkMap;
import com.flechazo.apisentinel.codeindex.parser.RouteEntry;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.PassiveFinding;
import com.flechazo.apisentinel.model.VulnType;import com.flechazo.apisentinel.repository.ApiRepository;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * MCP tool implementations exposing API-Sentinel's capabilities to external
 * Claude. Read-only tools query the repository; analyze_api triggers the real
 * Pipeline/Agent facades (the only entry points that handle task tracking,
 * persistence and reporting) and bridges the async callback to a blocking
 * wait. Facades live in the ui package and are package-private, so they are
 * injected as method references through {@link AnalysisTrigger}.
 */
public class McpTools {

    /** Bridge to the package-private facades (Pipeline/Agent) via method ref. */
    @FunctionalInterface
    public interface AnalysisTrigger {
        void trigger(ApiEntry entry, LlmProvider provider, Runnable onDone);
    }

    /** Result of a tool call: text payload + error flag. */
    public record ToolResult(String text, boolean isError) {
        static ToolResult ok(String text) { return new ToolResult(text, false); }
        static ToolResult error(String text) { return new ToolResult(text, true); }
    }

    private static final long ANALYZE_TIMEOUT_SEC = 600;

    private final ApiRepository repository;
    private final LlmProviderFactory providerFactory;
    private final ConfigManager configManager;
    private final CodeIndexService codeIndexService;
    private final LeveledLogger logger;

    private volatile AnalysisTrigger pipelineTrigger;
    private volatile AnalysisTrigger agentTrigger;
    private final Semaphore analyzeSlots = new Semaphore(2);

    /** MontoyaApi injected by the extension — needed by read-only tools that
     *  read proxy state (none today, but plumbed for future). Null in tests. */
    private volatile burp.api.montoya.MontoyaApi montoyaApi;
    public void setMontoyaApi(burp.api.montoya.MontoyaApi api) { this.montoyaApi = api; }

    /** Live BrowserService (null when browser disabled) — injected so the MCP
     *  layer can expose DOM XSS / SPA discovery / render tools. */
    private volatile BrowserService browserService;
    public void setBrowserService(BrowserService svc) { this.browserService = svc; }

    /** Shared OOB collector (injected) so SSRF/blind-callback tools exposed over
     *  MCP correlate against the same poller the rest of the plugin uses. */
    private volatile OobService oobService;
    public void setOobService(OobService svc) { this.oobService = svc; }

    /** Optional login-profile manager — when set, browser_login is exposed. */
    private volatile com.flechazo.apisentinel.config.LoginProfileManager loginProfileManager;
    public void setLoginProfileManager(com.flechazo.apisentinel.config.LoginProfileManager m) {
        this.loginProfileManager = m;
    }

    // ======================== MCP sessions ========================

    /** Session id used when a client sends no {@code Mcp-Session-Id} header
     *  (older clients / raw curl). All such calls share one anonymous session. */
    static final String ANONYMOUS_SESSION = "__anon__";
    /** Idle sessions older than this are evicted (frees browser pages etc.). */
    private static final long SESSION_IDLE_MS = 30 * 60 * 1000L;

    private final java.util.concurrent.ConcurrentHashMap<String, McpSession> sessions =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** Active/dangerous agent tools — exposed over MCP only when
     *  {@code mcpAllowActiveTools=true}. Everything else (read-only white-box,
     *  browser render/discover/dom_xss, notes, meta) is always available. */
    private static final java.util.Set<String> ACTIVE_TOOLS = java.util.Set.of(
            "send_request", "active_probe", "run_sandboxed_code", "browser_interact",
            "browser_login", "browser_explore", "browser_auto_crawl", "waf_bypass_retry",
            "generate_payloads", "test_auth_bypass", "verify_boolean_blind", "verify_timing_blind",
            "verify_xss_reflection", "verify_ssti", "verify_path_traversal", "verify_xxe",
            "verify_business_logic", "chain_hunter", "dispatch_explore_agent", "generate_oob_probe");

    /** Fired after validate_findings persists a verdict, so the extension
     *  can refresh the API table + detail panels (the mutation bypasses the
     *  repository's change notification because it acts on the entry directly). */
    private Runnable onUiRefresh;
    public void setOnUiRefresh(Runnable r) { this.onUiRefresh = r; }

    /** Event queue for push-style notifications. External clients poll via
     *  {@code get_latest_events} instead of needing SSE. */
    private final ConcurrentLinkedQueue<McpEvent> eventQueue = new ConcurrentLinkedQueue<>();
    private static final int MAX_EVENT_QUEUE = 200;

    /** An event emitted by the analysis engine — consumed by MCP clients. */
    public record McpEvent(long timestamp, String type, String path, String payload) {
        public static McpEvent analysisComplete(String path, String risk, int confirmed, int suspected) {
            return new McpEvent(System.currentTimeMillis(), "analysis_complete", path,
                    String.format("{\"risk\":\"%s\",\"confirmed\":%d,\"suspected\":%d}", risk, confirmed, suspected));
        }
        public static McpEvent highRiskFound(String path, String title) {
            return new McpEvent(System.currentTimeMillis(), "high_risk_found", path,
                    "{\"title\":\"" + escapeJson(title) + "\"}");
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** Push an event for external MCP clients to consume. */
    public void pushEvent(McpEvent event) {
        eventQueue.add(event);
        while (eventQueue.size() > MAX_EVENT_QUEUE) eventQueue.poll();
    }

    /** Drain and return all pending events (poll model). */
    public List<McpEvent> drainEvents() {
        List<McpEvent> events = new ArrayList<>();
        McpEvent e;
        while ((e = eventQueue.poll()) != null) events.add(e);
        return events;
    }

    public McpTools(ApiRepository repository, LlmProviderFactory providerFactory,
                    ConfigManager configManager, CodeIndexService codeIndexService,
                    LeveledLogger logger) {
        this.repository = repository;
        this.providerFactory = providerFactory;
        this.configManager = configManager;
        this.codeIndexService = codeIndexService;
        this.logger = logger;
    }

    /** Injected by the extension after the UI (and thus the facades) exist. */
    public void setAnalysisTriggers(AnalysisTrigger pipelineTrigger, AnalysisTrigger agentTrigger) {
        this.pipelineTrigger = pipelineTrigger;
        this.agentTrigger = agentTrigger;
    }

    // ======================== session lifecycle ========================

    /** Get (or lazily create) the session for this id, evicting stale ones. */
    private McpSession sessionFor(String sessionId) {
        String id = (sessionId == null || sessionId.isBlank()) ? ANONYMOUS_SESSION : sessionId;
        evictIdle();
        McpSession s = sessions.computeIfAbsent(id, k ->
                new McpSession(k, new FindingEvidenceStore(logger), new ProgressiveToolDisclosure(logger)));
        s.touch();
        return s;
    }

    private void evictIdle() {
        long now = System.currentTimeMillis();
        sessions.entrySet().removeIf(e -> now - e.getValue().lastAccess > SESSION_IDLE_MS);
    }

    /** Drop all sessions (extension unload). */
    public void closeAllSessions() { sessions.clear(); }

    /** Mirror ChatController's AnalysisConfig assembly so MCP tools behave
     *  exactly like the built-in conversational loop. */
    private AnalysisConfig buildAnalysisConfig() {
        var c = configManager.getConfig();
        boolean authTestEnabled = c.isUnauthorizedDetectionEnabled();
        return AnalysisConfig.forPipeline(c, authTestEnabled);
    }

    /** Build a full, stateful ToolContext + registry bound to {@code entry},
     *  reusing the session's persistent stores. Mirrors AgentLoop/ChatController
     *  wiring so every agent tool works identically over MCP. */
    private void rebuildContext(McpSession s, ApiEntry entry) {
        var c = configManager.getConfig();
        ToolContext ctx = new ToolContext(entry, providerFactory.getFirstAvailable(), montoyaApi,
                codeIndexService, c.getCodeRepos(), buildAnalysisConfig(), logger, oobService);
        if (browserService != null) ctx.setBrowserService(browserService);
        ctx.setApiRepository(repository);
        ctx.setAppConfig(c);
        if (loginProfileManager != null) ctx.setLoginProfileManager(loginProfileManager);
        ctx.setProgressiveToolDisclosure(s.disclosure);
        ctx.setFindingEvidenceStore(s.findingStore);
        ctx.setIncludeRawCredentials(c.isIncludeRawCredentialsInLlm());

        StandardToolRegistry.Tools built = StandardToolRegistry.build(ctx, false);
        s.tools = built;
        s.ctx = ctx;
        s.registry = built.registry();
        s.currentPath = entry != null ? entry.getApiPath() : null;
    }

    /** Ensure the session's registry is bound to the endpoint referenced by
     *  {@code path} (or a general context when path is null/unknown). Rebuilds
     *  only when the target changes — persistent stores are preserved. */
    private void ensureContext(McpSession s, String path) {
        ApiEntry entry = (path != null && !path.isBlank())
                ? repository.findByPath(path).orElse(null) : null;
        String wantPath = entry != null ? entry.getApiPath() : null;
        if (s.registry == null || !java.util.Objects.equals(s.currentPath, wantPath)) {
            rebuildContext(s, entry);
        }
    }

    /** Whether a registry tool may be exposed/called over MCP right now. */
    private boolean toolAllowed(String name) {
        if (!ACTIVE_TOOLS.contains(name)) return true;
        return configManager.getConfig().isMcpAllowActiveTools();
    }

    // ======================== tool registry ========================

    /** Backward-compatible: anonymous session (tests / clients without a
     *  session header). */
    public List<McpProtocol.ToolDef> listTools() {
        return listTools(null);
    }

    public List<McpProtocol.ToolDef> listTools(String sessionId) {
        List<McpProtocol.ToolDef> tools = new ArrayList<>();

        tools.add(new McpProtocol.ToolDef("list_apis",
                "List API endpoints captured by API-Sentinel, with method, path, domain, "
              + "risk status and whether they have traffic/passive findings. "
              + "Optionally filter by domain or risk level.",
                McpProtocol.stringSchema(props(
                        "domain", "optional: only APIs on this domain",
                        "risk", "optional: filter by risk (HIGH/MEDIUM/LOW/SAFE/--)"), null)));

        tools.add(new McpProtocol.ToolDef("get_api_detail",
                "Get full detail for one API endpoint: latest AI verdict, passive findings, "
              + "analysis history and traffic metadata. Use before deciding to analyze.",
                McpProtocol.stringSchema(props("path", "API path, e.g. /api/users/{id}"),
                        List.of("path"))));

        tools.add(new McpProtocol.ToolDef("get_passive_findings",
                "Get passive detection findings (sensitive info / heuristics / unauthorized probe) "
              + "for one API endpoint.",
                McpProtocol.stringSchema(props("path", "API path"), List.of("path"))));

        tools.add(new McpProtocol.ToolDef("get_analysis_history",
                "Get the AI analysis history for one API endpoint.",
                McpProtocol.stringSchema(props("path", "API path"), List.of("path"))));

        tools.add(new McpProtocol.ToolDef("analyze_api",
                "Trigger a full AI security analysis (Pipeline or Agent mode) on one API endpoint "
              + "and wait for the verdict. This runs the real 6-stage pipeline / ReAct agent "
              + "(may take 1-5 minutes). Returns the final verdict JSON.",
                McpProtocol.stringSchema(props(
                        "path", "API path to analyze",
                        "mode", "optional: 'pipeline' (default) or 'agent'"),
                        List.of("path"))));

        tools.add(new McpProtocol.ToolDef("search_code",
                "Search the indexed source-code repositories by regex keyword. "
              + "Returns matching file/line/context triples.",
                McpProtocol.stringSchema(props(
                        "keyword", "regex keyword to grep for",
                        "repo", "optional: restrict to one repo name"),
                        List.of("keyword"))));

        tools.add(new McpProtocol.ToolDef("get_source_code",
                "Get the backend source code implementing an API endpoint (from the code index).",
                McpProtocol.stringSchema(props("path", "API path"), List.of("path"))));

        tools.add(new McpProtocol.ToolDef("audit_codebase",
                "Audit the indexed source repositories for dangerous sinks (SQL/command injection, "
              + "deserialization, SSRF, path traversal, XXE, SSTI, crypto, etc.) — white-box analysis "
              + "the official Burp MCP cannot do. Returns sinks grouped by file with type/line/snippet "
              + "and a trace hint. Pair with search_code / get_source_code to read the code and trace "
              + "interpolated variables back to their source, then map to an endpoint and verify.",
                McpProtocol.stringSchema(props(
                        "sink_type", "optional: filter by type (command/sql/file_access/deserialization/"
                                + "ssrf/crypto/insecure_random/xxe/ssti/crlf/open_redirect/nosql)",
                        "max_results", "optional: cap number of sinks returned (default 100)"),
                        null)));

        // Differential read-only tools reused from the Agent's toolset — each
        // runs against a per-call read-only ToolContext (no session state, no
        // request-sending), so they're safe to expose without Phase-2
        // sessionization. All are white-box / asset semantics the official
        // Burp MCP doesn't offer.
        for (McpProtocol.ToolDef td : exposedReadOnlyToolDefs()) {
            tools.add(td);
        }
        // Browser tools — DOM XSS / SPA discovery / render. Differential (the
        // official Burp MCP doesn't do DOM-level analysis). Gracefully report
        // "browser not enabled" when BrowserService is null.
        for (McpProtocol.ToolDef td : exposedBrowserToolDefs()) {
            tools.add(td);
        }

        tools.add(new McpProtocol.ToolDef("analyze_batch",
                "Batch-trigger AI analysis on multiple API endpoints and wait for all verdicts. "
              + "Concurrency is capped at 2. Each API may take 1-5 minutes.",
                McpProtocol.stringSchema(props(
                        "paths", "comma-separated list of API paths to analyze",
                        "mode", "optional: 'pipeline' (default) or 'agent'"),
                        List.of("paths"))));

        tools.add(new McpProtocol.ToolDef("get_untracked_apis",
                "Compare indexed code routes against captured traffic to find APIs that have "
              + "never been triggered. These are candidates for active discovery.",
                McpProtocol.stringSchema(props(
                        "domain", "optional: only APIs for this domain"), null)));

        tools.add(new McpProtocol.ToolDef("get_latest_events",
                "Get the latest analysis completion events (poll model). Returns all pending "
              + "events since the last call and clears the queue.",
                McpProtocol.stringSchema(null, null)));

        tools.add(new McpProtocol.ToolDef("ingest_traffic",
                "Register an API endpoint (and optionally the request/response that backs it) into "
              + "API-Sentinel so it shows up in the API table and can be analyzed. Use this for "
              + "endpoints the external brain discovered OUTSIDE Burp's proxy (they never flowed "
              + "through API-Sentinel's HTTP handler, so they aren't tracked yet). Creates a new "
              + "entry or updates an existing one on the same path.",
                McpProtocol.stringSchema(props(
                        "path", "API path, e.g. /api/users/{id} (required)",
                        "method", "optional: HTTP method (default GET, or inferred from request)",
                        "domain", "optional: host/domain of the endpoint",
                        "url", "optional: full request URL",
                        "request", "optional: raw HTTP request (enables later analysis)",
                        "response", "optional: raw HTTP response",
                        "status_code", "optional: HTTP status code"),
                        List.of("path"))));

        tools.add(new McpProtocol.ToolDef("validate_findings",
                "Submit candidate vulnerability findings together with the request/response "
              + "records that back them, and get a PROGRAMMATICALLY validated verdict. Two gates "
              + "run: (1) an evidence-schema check — each finding type must carry its required "
              + "evidence slots (e.g. SQLi needs baseline_response + injected_response + "
              + "response_diff + payload_used; IDOR needs session_a/session_b/anonymous responses "
              + "+ identity_proof); (2) VerdictValidator — the cited payload must appear in the "
              + "supplied requests, cited response text must match a real response, auth-class "
              + "findings need two different sessions on the same endpoint, informational-only "
              + "findings and HIGH-without-confirmed are downgraded. Findings that fail are demoted "
              + "to 'suspected' with a machine-readable reason in rejectionReasons — this gate "
              + "cannot be talked past with prose. Best paired with the official Burp MCP for "
              + "traffic. NOTE: byte-level grounding is strongest when the requests were actually "
              + "sent; a fully self-supplied submission is checked for internal consistency + "
              + "evidence completeness.",
                validateFindingsSchema()));

        // Full agent toolset (send_request, verify_*, browser login/interact/
        // explore, notes, request_tools, …) — the same arsenal the built-in
        // conversational loop uses. Bound to a stateful session ToolContext so
        // request-sending / browser pages persist across calls. Names already
        // present above (native curated tools) are NOT overridden; names in
        // ACTIVE_TOOLS are gated behind mcpAllowActiveTools.
        java.util.Set<String> nativeNames = new java.util.HashSet<>();
        for (McpProtocol.ToolDef td : tools) nativeNames.add(td.name());
        McpSession s = sessionFor(sessionId);
        synchronized (s.lock) {
            ensureContext(s, null);
            if (s.registry != null) {
                for (ToolDefinition def : s.registry.getDefinitions()) {
                    if (nativeNames.contains(def.name())) continue;   // curated version wins
                    if (!toolAllowed(def.name())) continue;           // gated active tool
                    tools.add(new McpProtocol.ToolDef(def.name(), def.description(), def.inputSchema()));
                }
            }
        }

        return tools;
    }

    /** Backward-compatible: anonymous session. */
    public ToolResult callTool(String name, JsonObject args) {
        return callTool(name, args, null);
    }

    public ToolResult callTool(String name, JsonObject args, String sessionId) {
        try {
            switch (name == null ? "" : name) {
                // Native curated tools handled below; anything else falls through
                // to the session registry (full agent arsenal).
                case "list_apis", "get_api_detail", "get_passive_findings",
                     "get_analysis_history", "analyze_api", "search_code",
                     "get_source_code", "audit_codebase", "read_file",
                     "trace_taint_source", "find_definition", "find_callers",
                     "map_sibling_endpoints", "browser_discover", "browser_dom_xss",
                     "browser_render", "analyze_batch", "get_untracked_apis",
                     "get_latest_events", "ingest_traffic", "validate_findings":
                    break;
                default:
                    return callAgentTool(name, args, sessionId);
            }
            return switch (name == null ? "" : name) {
                case "list_apis" -> listApis(args);
                case "get_api_detail" -> getApiDetail(args);
                case "get_passive_findings" -> getPassiveFindings(args);
                case "get_analysis_history" -> getAnalysisHistory(args);
                case "analyze_api" -> analyzeApi(args);
                case "search_code" -> searchCode(args);
                case "get_source_code" -> getSourceCode(args);
                case "audit_codebase" -> auditCodebase(args);
                case "read_file" -> runExposedTool(args, ReadFileTool::new);
                case "trace_taint_source" -> runExposedTool(args, TraceTaintSourceTool::new);
                case "find_definition" -> runExposedTool(args, FindDefinitionTool::new);
                case "find_callers" -> runExposedTool(args, FindCallersTool::new);
                case "map_sibling_endpoints" -> runExposedTool(args, MapSiblingEndpointsTool::new);
                case "browser_discover" -> runBrowserTool(args, BrowserDiscoverTool::new);
                case "browser_dom_xss" -> runBrowserTool(args, BrowserDomXssTool::new);
                case "browser_render" -> runBrowserTool(args, BrowserRenderTool::new);
                case "analyze_batch" -> analyzeBatch(args);
                case "get_untracked_apis" -> getUntrackedApis(args);
                case "get_latest_events" -> getLatestEvents();
                case "ingest_traffic" -> ingestTraffic(args);
                case "validate_findings" -> validateFindings(args);
                default -> ToolResult.error("Unknown tool: " + name);
            };
        } catch (Exception e) {
            if (logger != null) logger.warn("[MCP] tool '%s' failed: %s", name, e.getMessage());
            return ToolResult.error("Tool error: " + e.getMessage());
        }
    }

    /**
     * Route a call to the full agent toolset via the session's stateful
     * registry — the same pre→execute→post pipeline the built-in loop uses.
     * Rebuilds the session context against the endpoint named by args.path so
     * tools that read {@code ctx.entry()} target the right endpoint. Calls
     * within one session are serialized on {@link McpSession#lock}.
     */
    private ToolResult callAgentTool(String name, JsonObject args, String sessionId) {
        if (!toolAllowed(name)) {
            return ToolResult.error("Tool '" + name + "' is an active/dangerous tool disabled over MCP. "
                    + "Enable it via config mcpAllowActiveTools=true (lets the external brain drive "
                    + "attack traffic through Burp).");
        }
        McpSession s = sessionFor(sessionId);
        synchronized (s.lock) {
            ensureContext(s, str(args, "path"));
            if (s.registry == null || !s.registry.hasTool(name)) {
                return ToolResult.error("Unknown tool: " + name);
            }
            String result = s.registry.executeTool(name, args == null ? "{}" : args.toString());
            // Harvest any requests this tool sent (send_request, and verify_*/
            // active_probe which route through the shared SendRequestTool) into
            // the endpoint's test-case list, mirroring the internal Agent.
            syncSentTraffic(s);
            // executeTool returns tool JSON (or an {"error":...} envelope); treat
            // an error envelope as an MCP error so the client sees isError=true.
            boolean isErr = result != null && result.stripLeading().startsWith("{\"error\"");
            return new ToolResult(result == null ? "{}" : result, isErr);
        }
    }

    /**
     * Persist the session's accumulated sent requests into the focused
     * endpoint's analysis record so they appear in the Repeater's 测试用例列表
     * (and survive restarts), exactly like an internal Agent/Chat run. Uses one
     * reusable "MCP" record per path (remove+add to update) to avoid spamming
     * the analysis history. Called under the session lock.
     */
    private void syncSentTraffic(McpSession s) {
        if (s.tools == null || s.tools.sendTool() == null) return;
        String path = s.currentPath;
        if (path == null || path.isBlank()) return;   // no endpoint focus to attach to
        List<PayloadResult> sent = s.tools.sendTool().getPayloadResults();
        if (sent == null || sent.isEmpty()) return;
        ApiEntry entry = repository.findByPath(path).orElse(null);
        if (entry == null) return;

        try {
            // Replace the previous MCP-traffic record for this path with a fresh
            // one carrying the full current set (records are immutable).
            AnalysisRecord old = s.trafficRecordByPath.get(path);
            if (old != null && old.hasPipelineResult() && old.pipelineResult().payloadResults() != null
                    && old.pipelineResult().payloadResults().size() == sent.size()) {
                return;   // nothing new since last sync — skip the rebuild/save
            }
            if (old != null) entry.removeAnalysisRecord(old);

            AnalysisResult traffic = new AnalysisResult(
                    List.of(), "", AnalysisResult.RiskLevel.NONE, 0, 0, "external-mcp", null);
            FinalVerdict v = new FinalVerdict("LOW", List.of(), List.of(),
                    "MCP 发送的测试流量（" + sent.size() + " 条请求）", "", 0, List.of());
            PipelineResult pr = new PipelineResult(
                    traffic, "", List.of(), new ArrayList<>(sent), v, Map.of());
            AnalysisRecord rec = new AnalysisRecord("MCP", traffic).withPipelineResult(pr);
            entry.addAnalysisRecord(rec);
            s.trafficRecordByPath.put(path, rec);

            repository.save();
            if (onUiRefresh != null) onUiRefresh.run();
        } catch (Exception e) {
            if (logger != null) logger.warn("[MCP] syncSentTraffic failed: %s", e.getMessage());
        }
    }

    // ======================== read-only tools ========================

    private ToolResult listApis(JsonObject args) {
        String domain = str(args, "domain");
        String risk = str(args, "risk");
        List<ApiEntry> entries = (domain != null && !domain.isBlank())
                ? repository.findByDomain(domain)
                : repository.findAll();

        JsonArray arr = new JsonArray();
        for (ApiEntry e : entries) {
            String r = e.getDisplayRisk();
            if (risk != null && !risk.isBlank() && !risk.equalsIgnoreCase(r)) continue;
            JsonObject o = new JsonObject();
            o.addProperty("method", e.getHttpMethod());
            o.addProperty("path", e.getApiPath());
            o.addProperty("domain", e.getDomain());
            o.addProperty("status", e.getStatus().name());
            o.addProperty("risk", r);
            o.addProperty("lastStatusCode", e.getLastStatusCode());
            o.addProperty("hasTraffic", e.hasTrafficData());
            o.addProperty("passiveRisk", e.getMaxPassiveRisk());
            arr.add(o);
        }
        JsonObject out = new JsonObject();
        out.addProperty("count", arr.size());
        out.add("apis", arr);
        return ToolResult.ok(out.toString());
    }

    private ToolResult getApiDetail(JsonObject args) {
        ApiEntry e = requireEntry(args);
        if (e == null) return ToolResult.error("API not found: " + str(args, "path"));

        JsonObject o = new JsonObject();
        o.addProperty("method", e.getHttpMethod());
        o.addProperty("path", e.getApiPath());
        o.addProperty("domain", e.getDomain());
        o.addProperty("status", e.getStatus().name());
        o.addProperty("risk", e.getDisplayRisk());
        o.addProperty("lastUrl", e.getLastUrl());
        o.addProperty("lastStatusCode", e.getLastStatusCode());
        o.addProperty("hasTraffic", e.hasTrafficData());
        if (e.getNote() != null && !e.getNote().isBlank()) o.addProperty("note", e.getNote());

        AnalysisRecord latest = e.getLatestAnalysisRecord();
        if (latest != null && latest.hasPipelineResult() && latest.pipelineResult().verdict() != null) {
            o.add("latestVerdict", verdictToJson(latest.pipelineResult().verdict()));
        }
        o.addProperty("analysisCount", e.getAnalysisHistory().size());
        o.addProperty("passiveFindingCount", e.getPassiveFindings().size());
        return ToolResult.ok(o.toString());
    }

    private ToolResult getPassiveFindings(JsonObject args) {
        ApiEntry e = requireEntry(args);
        if (e == null) return ToolResult.error("API not found: " + str(args, "path"));
        JsonArray arr = new JsonArray();
        for (PassiveFinding f : e.getPassiveFindings()) {
            JsonObject o = new JsonObject();
            o.addProperty("source", f.source().name());
            o.addProperty("risk", f.risk());
            o.addProperty("category", f.category());
            o.addProperty("title", f.title());
            o.addProperty("evidence", f.evidence());
            if (f.remediation() != null && !f.remediation().isBlank()) o.addProperty("remediation", f.remediation());
            arr.add(o);
        }
        JsonObject out = new JsonObject();
        out.addProperty("path", e.getApiPath());
        out.addProperty("count", arr.size());
        out.add("findings", arr);
        return ToolResult.ok(out.toString());
    }

    private ToolResult getAnalysisHistory(JsonObject args) {
        ApiEntry e = requireEntry(args);
        if (e == null) return ToolResult.error("API not found: " + str(args, "path"));
        JsonArray arr = new JsonArray();
        for (AnalysisRecord rec : e.getAnalysisHistory()) {
            JsonObject o = new JsonObject();
            o.addProperty("id", rec.id());
            o.addProperty("timestamp", rec.timestamp());
            o.addProperty("mode", rec.mode());
            if (rec.hasPipelineResult() && rec.pipelineResult().verdict() != null) {
                FinalVerdict v = rec.pipelineResult().verdict();
                o.addProperty("overallRisk", v.overallRisk());
                o.addProperty("summary", v.summary());
            }
            arr.add(o);
        }
        JsonObject out = new JsonObject();
        out.addProperty("path", e.getApiPath());
        out.addProperty("count", arr.size());
        out.add("history", arr);
        return ToolResult.ok(out.toString());
    }

    // ======================== analysis trigger ========================

    private ToolResult analyzeApi(JsonObject args) {
        ApiEntry e = requireEntry(args);
        if (e == null) return ToolResult.error("API not found: " + str(args, "path"));
        String mode = str(args, "mode");
        boolean useAgent = "agent".equalsIgnoreCase(mode);

        AnalysisTrigger trigger = useAgent ? agentTrigger : pipelineTrigger;
        if (trigger == null) {
            return ToolResult.error("Analysis engine not ready (UI still initializing). Retry shortly.");
        }
        LlmProvider provider = providerFactory.getFirstAvailable();
        if (provider == null) {
            return ToolResult.error("No AI provider configured. Set one in Settings → AI Settings.");
        }
        if (!analyzeSlots.tryAcquire()) {
            return ToolResult.error("Too many concurrent MCP analyses (limit 2). Wait and retry.");
        }

        final String path = e.getApiPath();
        try {
            CompletableFuture<Void> done = new CompletableFuture<>();
            trigger.trigger(e, provider, () -> done.complete(null));
            try {
                done.get(ANALYZE_TIMEOUT_SEC, TimeUnit.SECONDS);
            } catch (java.util.concurrent.TimeoutException te) {
                return ToolResult.ok("{\"status\":\"still_running\",\"path\":\"" + path
                        + "\",\"note\":\"Analysis is still running after " + ANALYZE_TIMEOUT_SEC
                        + "s. Query get_analysis_history later for the result.\"}");
            }

            ApiEntry fresh = repository.findByPath(path).orElse(e);
            AnalysisRecord latest = fresh.getLatestAnalysisRecord();
            if (latest == null || !latest.hasPipelineResult() || latest.pipelineResult().verdict() == null) {
                return ToolResult.ok("{\"status\":\"completed\",\"path\":\"" + path
                        + "\",\"note\":\"Analysis finished but no verdict was produced.\"}");
            }
            JsonObject out = new JsonObject();
            out.addProperty("status", "completed");
            out.addProperty("path", path);
            out.addProperty("mode", useAgent ? "agent" : "pipeline");
            out.add("verdict", verdictToJson(latest.pipelineResult().verdict()));
            return ToolResult.ok(out.toString());
        } catch (Exception ex) {
            return ToolResult.error("Analysis failed: " + ex.getMessage());
        } finally {
            analyzeSlots.release();
        }
    }

    // ======================== code search ========================

    private ToolResult searchCode(JsonObject args) {
        String keyword = str(args, "keyword");
        if (keyword == null || keyword.isBlank()) return ToolResult.error("keyword is required");
        var repos = configManager.getConfig().getCodeRepos();
        String repoFilter = str(args, "repo");
        if (repoFilter != null && !repoFilter.isBlank()) {
            repos = repos.stream().filter(r -> repoFilter.equalsIgnoreCase(r.getName())).toList();
        }
        if (repos == null || repos.isEmpty()) {
            return ToolResult.error("No code repositories configured. Add one in Settings → Code Repos.");
        }
        RepoGrepper.GrepOutcome outcome;
        try {
            // P2-9: ReDoS guard on MCP-provided regex (unauthenticated caller).
            outcome = RepoGrepper.searchEx(repos,
                    com.flechazo.apisentinel.util.RegexSafety.safeCompile(keyword), null, 50, 1, false);
        } catch (Exception e) {
            return ToolResult.error("Invalid regex: " + e.getMessage());
        }
        // P0-12 hardening: MCP clients (typically an external agent) read
        // the match list directly. Returning an empty list when the repo
        // was unreadable looks identical to "nothing matched" — surface
        // the failure explicitly so the caller can react instead of
        // silently acting on stale / absent code.
        if (!outcome.isAvailable()) {
            return ToolResult.error("repo_unavailable: " + outcome.unavailableReason());
        }
        List<RepoGrepper.GrepMatch> matches = outcome.matches();
        JsonArray arr = new JsonArray();
        for (RepoGrepper.GrepMatch m : matches) {
            JsonObject o = new JsonObject();
            o.addProperty("file", m.file().toString());
            o.addProperty("line", m.line());
            o.addProperty("context", m.context());
            arr.add(o);
        }
        JsonObject out = new JsonObject();
        out.addProperty("keyword", keyword);
        out.addProperty("count", arr.size());
        out.add("matches", arr);
        return ToolResult.ok(out.toString());
    }

    private ToolResult getSourceCode(JsonObject args) {
        ApiEntry e = requireEntry(args);
        if (e == null) return ToolResult.error("API not found: " + str(args, "path"));
        List<RouteEntry> routes = codeIndexService.findByPath(e.getApiPath());
        if (routes == null || routes.isEmpty()) {
            return ToolResult.ok("{\"path\":\"" + e.getApiPath()
                    + "\",\"note\":\"No indexed source route matched this path.\"}");
        }
        JsonArray arr = new JsonArray();
        for (RouteEntry route : routes) {
            String code = codeIndexService.getSourceCode(route);
            JsonObject o = new JsonObject();
            o.addProperty("file", route.sourceFile() != null ? route.sourceFile().toString() : "");
            o.addProperty("method", route.httpMethod());
            o.addProperty("handler", route.className() + "." + route.methodName());
            o.addProperty("location", route.displayLocation());
            o.addProperty("code", code == null ? "" : code.length() > 4000 ? code.substring(0, 4000) + "\n...[truncated]" : code);
            arr.add(o);
        }
        JsonObject out = new JsonObject();
        out.addProperty("path", e.getApiPath());
        out.addProperty("count", arr.size());
        out.add("sources", arr);
        return ToolResult.ok(out.toString());
    }

    // ======================== batch + events ========================

    /** Stateless white-box audit of indexed code repos — mirrors the Agent's
     *  AuditCodebaseTool but reads {@link CodeIndexService} directly (no
     *  ToolContext needed), so the external brain can discover dangerous sinks
     *  the way the internal Agent does. */
    private ToolResult auditCodebase(JsonObject args) {
        if (codeIndexService == null) {
            return ToolResult.error("No code index service configured.");
        }
        SinkMap sinkMap = codeIndexService.getSinkMap();
        if (sinkMap == null || sinkMap.totalSinkCount() == 0) {
            return ToolResult.error("No sinks indexed. Index a code repository first (Settings -> Code Repos).");
        }
        SinkMap.SinkType typeFilter = parseSinkType(str(args, "sink_type"));
        int maxResults = Math.min(Math.max(intOr(args, "max_results", 100), 1), 500);
        List<SinkMap.SinkEntry> sinks = typeFilter != null
                ? sinkMap.allSinksOfType(typeFilter) : sinkMap.allSinks();

        Map<String, List<SinkMap.SinkEntry>> byFile = new LinkedHashMap<>();
        for (SinkMap.SinkEntry s : sinks) {
            byFile.computeIfAbsent(s.file(), k -> new ArrayList<>()).add(s);
        }
        JsonObject out = new JsonObject();
        out.addProperty("total_sinks", sinks.size());
        out.addProperty("files_with_sinks", byFile.size());
        JsonArray filesArr = new JsonArray();
        int emitted = 0;
        boolean truncated = false;
        outer:
        for (Map.Entry<String, List<SinkMap.SinkEntry>> e : byFile.entrySet()) {
            JsonObject fo = new JsonObject();
            fo.addProperty("file", e.getKey());
            JsonArray sinksArr = new JsonArray();
            for (SinkMap.SinkEntry s : e.getValue()) {
                if (emitted >= maxResults) { truncated = true; break outer; }
                JsonObject so = new JsonObject();
                so.addProperty("line", s.line());
                so.addProperty("type", s.type().name());
                so.addProperty("label", SinkAnnotator.label(s.type()));
                String hint = SinkAnnotator.traceHint(s.type());
                if (!hint.isEmpty()) so.addProperty("trace_hint", hint);
                String snippet = s.snippet();
                if (snippet != null && snippet.length() > 160) snippet = snippet.substring(0, 157) + "...";
                so.addProperty("snippet", snippet);
                sinksArr.add(so);
                emitted++;
            }
            fo.add("sinks", sinksArr);
            filesArr.add(fo);
        }
        out.add("files", filesArr);
        if (truncated) { out.addProperty("truncated", true); out.addProperty("returned", emitted); }
        return ToolResult.ok(out.toString());
    }

    // ======================== exposed read-only Agent tools ========================

    /** Tool defs for the differential read-only tools advertised in tools/list.
     *  Each tool's name/description/inputSchema are independent of ctx, so we
     *  instantiate with a null ctx purely to harvest its definition. */
    private List<McpProtocol.ToolDef> exposedReadOnlyToolDefs() {
        List<McpProtocol.ToolDef> out = new ArrayList<>();
        for (java.util.function.Function<ToolContext, AgentTool> ctor : exposedToolCtors()) {
            try {
                AgentTool t = ctor.apply(null);
                var td = t.toDefinition();
                out.add(new McpProtocol.ToolDef(td.name(), td.description(), td.inputSchema()));
            } catch (Exception ignored) {
                // A tool that NPEs on null ctx during definition harvest — skip it.
            }
        }
        return out;
    }

    /** Constructors of the read-only differential tools exposed over MCP. */
    private static List<java.util.function.Function<ToolContext, AgentTool>> exposedToolCtors() {
        return List.of(
                ReadFileTool::new,
                TraceTaintSourceTool::new,
                FindDefinitionTool::new,
                FindCallersTool::new,
                MapSiblingEndpointsTool::new);
    }

    /** Build a read-only ToolContext for one MCP call: entry looked up by the
     *  optional {@code path} arg, code repos + code index + logger from this
     *  McpTools, montoyaApi if injected. No provider, no oob, no session
     *  mutation — safe for concurrent external calls. */
    private ToolContext buildReadOnlyContext(JsonObject args) {
        String path = str(args, "path");
        ApiEntry entry = (path != null && !path.isBlank())
                ? repository.findByPath(path).orElse(null) : null;
        List<com.flechazo.apisentinel.config.CodeRepo> repos =
                configManager != null ? configManager.getConfig().getCodeRepos() : List.of();
        return new ToolContext(entry, null, montoyaApi, codeIndexService, repos, null, logger, null);
    }

    /** Run one exposed read-only tool: build ctx from args, instantiate, execute. */
    private ToolResult runExposedTool(JsonObject args,
                                       java.util.function.Function<ToolContext, AgentTool> ctor) {
        try {
            ToolContext ctx = buildReadOnlyContext(args);
            AgentTool tool = ctor.apply(ctx);
            String result = tool.execute(args.toString());
            return ToolResult.ok(result == null ? "{}" : result);
        } catch (Exception e) {
            if (logger != null) logger.warn("[MCP] exposed tool failed: %s", e.getMessage());
            return ToolResult.error("Tool error: " + e.getMessage());
        }
    }

    // ---- browser tools (2-arg ctor: ctx + BrowserService) ----

    private List<McpProtocol.ToolDef> exposedBrowserToolDefs() {
        List<McpProtocol.ToolDef> out = new ArrayList<>();
        for (java.util.function.BiFunction<ToolContext, BrowserService, AgentTool> ctor : exposedBrowserToolCtors()) {
            try {
                AgentTool t = ctor.apply(null, null);
                var td = t.toDefinition();
                out.add(new McpProtocol.ToolDef(td.name(), td.description(), td.inputSchema()));
            } catch (Exception ignored) {}
        }
        return out;
    }

    private static List<java.util.function.BiFunction<ToolContext, BrowserService, AgentTool>> exposedBrowserToolCtors() {
        return List.of(
                BrowserDiscoverTool::new,
                BrowserDomXssTool::new,
                BrowserRenderTool::new);
    }

    private ToolResult runBrowserTool(JsonObject args,
                                      java.util.function.BiFunction<ToolContext, BrowserService, AgentTool> ctor) {
        try {
            ToolContext ctx = buildReadOnlyContext(args);
            AgentTool tool = ctor.apply(ctx, browserService);
            String result = tool.execute(args.toString());
            return ToolResult.ok(result == null ? "{}" : result);
        } catch (Exception e) {
            if (logger != null) logger.warn("[MCP] browser tool failed: %s", e.getMessage());
            return ToolResult.error("Tool error: " + e.getMessage());
        }
    }

    private static SinkMap.SinkType parseSinkType(String s) {
        if (s == null || s.isBlank()) return null;
        return switch (s.trim().toLowerCase()) {
            case "command", "cmd", "rce" -> SinkMap.SinkType.COMMAND;
            case "sql", "sqli" -> SinkMap.SinkType.SQL;
            case "file_access", "file", "path_traversal", "lfi" -> SinkMap.SinkType.FILE_ACCESS;
            case "deserialization", "deser" -> SinkMap.SinkType.DESERIALIZATION;
            case "ssrf" -> SinkMap.SinkType.SSRF;
            case "crypto", "weak_crypto" -> SinkMap.SinkType.CRYPTO;
            case "insecure_random", "rng" -> SinkMap.SinkType.INSECURE_RANDOM;
            case "xxe" -> SinkMap.SinkType.XXE;
            case "ssti" -> SinkMap.SinkType.SSTI;
            case "crlf" -> SinkMap.SinkType.CRLF;
            case "open_redirect", "redirect" -> SinkMap.SinkType.OPEN_REDIRECT;
            case "nosql" -> SinkMap.SinkType.NOSQL;
            default -> null;
        };
    }

    private ToolResult analyzeBatch(JsonObject args) {
        String pathsStr = str(args, "paths");
        if (pathsStr == null || pathsStr.isBlank()) return ToolResult.error("paths is required (comma-separated)");
        String mode = str(args, "mode");
        boolean useAgent = "agent".equalsIgnoreCase(mode);

        AnalysisTrigger trigger = useAgent ? agentTrigger : pipelineTrigger;
        if (trigger == null) return ToolResult.error("Analysis engine not ready.");

        LlmProvider provider = providerFactory.getFirstAvailable();
        if (provider == null) return ToolResult.error("No AI provider configured.");

        String[] paths = pathsStr.split(",");
        List<String> validPaths = new ArrayList<>();
        List<String> skipped = new ArrayList<>();

        for (String p : paths) {
            String trimmed = p.trim();
            if (trimmed.isEmpty()) continue;
            Optional<ApiEntry> opt = repository.findByPath(trimmed);
            if (opt.isPresent()) {
                validPaths.add(trimmed);
            } else {
                skipped.add(trimmed);
            }
        }

        JsonObject out = new JsonObject();
        out.addProperty("total", paths.length);
        out.addProperty("valid", validPaths.size());
        out.addProperty("skipped", skipped.size());
        if (!skipped.isEmpty()) {
            JsonArray sk = new JsonArray();
            skipped.forEach(sk::add);
            out.add("skippedPaths", sk);
        }

        JsonArray results = new JsonArray();
        int completed = 0;
        int failed = 0;

        for (String path : validPaths) {
            if (!analyzeSlots.tryAcquire()) {
                // wait for a slot
                try {
                    analyzeSlots.acquire();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            try {
                ApiEntry e = repository.findByPath(path).orElse(null);
                if (e == null) { failed++; analyzeSlots.release(); continue; }

                CompletableFuture<Void> done = new CompletableFuture<>();
                trigger.trigger(e, provider, () -> done.complete(null));
                try {
                    done.get(ANALYZE_TIMEOUT_SEC, TimeUnit.SECONDS);
                } catch (Exception ex) {
                    // timeout — continue to next
                }

                ApiEntry fresh = repository.findByPath(path).orElse(e);
                AnalysisRecord latest = fresh.getLatestAnalysisRecord();
                JsonObject r = new JsonObject();
                r.addProperty("path", path);
                if (latest != null && latest.hasPipelineResult() && latest.pipelineResult().verdict() != null) {
                    FinalVerdict v = latest.pipelineResult().verdict();
                    r.addProperty("risk", v.overallRisk());
                    r.addProperty("confirmed", v.confirmedVulns() != null ? v.confirmedVulns().size() : 0);
                    r.addProperty("suspected", v.suspectedVulns() != null ? v.suspectedVulns().size() : 0);
                    completed++;
                    pushEvent(McpEvent.analysisComplete(path, v.overallRisk(),
                            v.confirmedVulns() != null ? v.confirmedVulns().size() : 0,
                            v.suspectedVulns() != null ? v.suspectedVulns().size() : 0));
                    if ("HIGH".equals(v.overallRisk()) && v.confirmedVulns() != null && !v.confirmedVulns().isEmpty()) {
                        pushEvent(McpEvent.highRiskFound(path, v.confirmedVulns().get(0).title()));
                    }
                } else {
                    r.addProperty("risk", "UNKNOWN");
                    r.addProperty("confirmed", 0);
                    r.addProperty("suspected", 0);
                    failed++;
                }
                results.add(r);
            } catch (Exception ex) {
                failed++;
                JsonObject r = new JsonObject();
                r.addProperty("path", path);
                r.addProperty("error", ex.getMessage());
                results.add(r);
            } finally {
                analyzeSlots.release();
            }
        }

        out.addProperty("completed", completed);
        out.addProperty("failed", failed);
        out.add("results", results);
        return ToolResult.ok(out.toString());
    }

    private ToolResult getUntrackedApis(JsonObject args) {
        String domain = str(args, "domain");
        Map<String, List<RouteEntry>> allRoutes = codeIndexService.getAllRoutes();
        if (allRoutes.isEmpty()) {
            return ToolResult.ok("{\"count\":0,\"note\":\"No code index available. Index a code repository first.\"}");
        }

        // Collect all captured paths (normalized) for comparison
        Set<String> capturedPaths = new HashSet<>();
        List<ApiEntry> allEntries = (domain != null && !domain.isBlank())
                ? repository.findByDomain(domain) : repository.findAll();
        for (ApiEntry e : allEntries) {
            capturedPaths.add(RouteEntry.normalize(e.getApiPath()));
        }

        // Find routes in code index that have no captured traffic
        JsonArray untracked = new JsonArray();
        int totalRoutes = 0;
        for (var entry : allRoutes.entrySet()) {
            for (RouteEntry route : entry.getValue()) {
                totalRoutes++;
                if (!capturedPaths.contains(route.normalizedPattern())) {
                    // Check if any similar path was captured (fuzzy match)
                    boolean hasSimilar = capturedPaths.stream()
                            .anyMatch(cp -> cp.contains(route.normalizedPattern())
                                    || route.normalizedPattern().contains(cp));
                    JsonObject o = new JsonObject();
                    o.addProperty("method", route.httpMethod());
                    o.addProperty("path", route.routePattern());
                    o.addProperty("normalizedPath", route.normalizedPattern());
                    o.addProperty("handler", route.className() + "." + route.methodName());
                    o.addProperty("sourceFile", route.sourceFile() != null ? route.sourceFile().toString() : "");
                    o.addProperty("line", route.startLine());
                    o.addProperty("hasSimilarCaptured", hasSimilar);
                    untracked.add(o);
                }
            }
        }

        JsonObject out = new JsonObject();
        out.addProperty("totalIndexedRoutes", totalRoutes);
        out.addProperty("capturedApis", capturedPaths.size());
        out.addProperty("untrackedCount", untracked.size());
        out.add("untracked", untracked);
        return ToolResult.ok(out.toString());
    }

    private ToolResult getLatestEvents() {
        List<McpEvent> events = drainEvents();
        JsonArray arr = new JsonArray();
        for (McpEvent e : events) {
            JsonObject o = new JsonObject();
            o.addProperty("timestamp", e.timestamp());
            o.addProperty("type", e.type());
            o.addProperty("path", e.path());
            o.addProperty("payload", e.payload());
            arr.add(o);
        }
        JsonObject out = new JsonObject();
        out.addProperty("count", arr.size());
        out.add("events", arr);
        return ToolResult.ok(out.toString());
    }

    // ======================== validate_findings ========================

    /**
     * Two-layer validation of externally-submitted findings.
     * Layer 1 — {@link EvidenceSchema}: required evidence slots per type.
     * Layer 2 — {@link VerdictValidator}: authenticity cross-checks.
     * Returns the merged, structured verdict (survivors + demotions + reasons).
     */
    /** Ingest an externally-discovered endpoint (optionally with traffic) into
     *  the repository so it appears in the API table and becomes analyzable.
     *  Browser-independent — this is the general bridge for traffic the external
     *  brain captured outside API-Sentinel's proxy. */
    private ToolResult ingestTraffic(JsonObject args) {
        String path = str(args, "path");
        if (path == null || path.isBlank()) {
            return ToolResult.error("ingest_traffic requires 'path'");
        }
        String request = strOr(args, "request", "");
        String method = str(args, "method");
        if (method == null || method.isBlank()) {
            String fromReq = httpMethodFromRaw(request);
            method = fromReq != null ? fromReq : "GET";
        }
        String domain = strOr(args, "domain", "");
        String url = strOr(args, "url", "");
        String response = strOr(args, "response", "");
        int statusCode = intOr(args, "status_code", 0);

        boolean created;
        ApiEntry entry = repository.findByPath(path).orElse(null);
        if (entry == null) {
            entry = new ApiEntry(method, path);
            if (!domain.isBlank()) entry.setDomain(domain);
            applyTraffic(entry, url, request, response, statusCode);
            repository.add(entry);   // fires change -> table refresh
            created = true;
        } else {
            if (method != null && !method.isBlank()) entry.setHttpMethod(method);
            if (!domain.isBlank()) entry.setDomain(domain);
            applyTraffic(entry, url, request, response, statusCode);
            repository.save();
            if (onUiRefresh != null) onUiRefresh.run();   // setters don't fire change
            created = false;
        }

        JsonObject out = new JsonObject();
        out.addProperty("path", path);
        out.addProperty("method", method);
        out.addProperty(created ? "created" : "updated", true);
        out.addProperty("hasTraffic", entry.hasTrafficData());
        return ToolResult.ok(out.toString());
    }

    /** Set the entry's last-seen traffic sample from ingested fields. */
    private static void applyTraffic(ApiEntry entry, String url, String request,
                                     String response, int statusCode) {
        if (url != null && !url.isBlank()) entry.setLastUrl(url);
        if (request != null && !request.isBlank()) entry.setLastRawRequest(request);
        if (response != null && !response.isBlank()) entry.setLastRawResponse(response);
        if (statusCode > 0) entry.setLastStatusCode(statusCode);
        entry.setLastSeenTimestamp(System.currentTimeMillis());
    }

    /** Extract the HTTP method from a raw request's request line. */
    private static String httpMethodFromRaw(String rawRequest) {
        if (rawRequest == null || rawRequest.isBlank()) return null;
        String firstLine = rawRequest.split("\r?\n", 2)[0].trim();
        int sp = firstLine.indexOf(' ');
        return sp > 0 ? firstLine.substring(0, sp).trim() : null;
    }

    private ToolResult validateFindings(JsonObject args) {
        if (args == null || !args.has("findings") || !args.get("findings").isJsonArray()) {
            return ToolResult.error("validate_findings requires a 'findings' array");
        }
        String overallRisk = strOr(args, "overall_risk", "LOW");
        String summary = strOr(args, "summary", "");
        String recommendations = strOr(args, "recommendations", "");
        String path = str(args, "path");

        // Parse supplied request/response records → PayloadResult (testCase=null,
        // Agent-mode shape). apiPathOf() will recover the path from the raw
        // request line, so auth cross-checks work without a TestCase.
        List<PayloadResult> payloads = new ArrayList<>();
        if (args.has("requests") && args.get("requests").isJsonArray()) {
            for (JsonElement el : args.getAsJsonArray("requests")) {
                if (!el.isJsonObject()) continue;
                JsonObject r = el.getAsJsonObject();
                payloads.add(new PayloadResult(
                        null,
                        strOr(r, "sent_request", ""),
                        strOr(r, "received_response", ""),
                        intOr(r, "status_code", 0),
                        0L,
                        boolOr(r, "anomaly_detected", false),
                        0L,
                        intOr(r, "execution_index", -1),
                        null,
                        0,
                        str(r, "auth_session"),
                        false));
            }
        }

        // Layer 1: evidence-schema completeness.
        List<ConfirmedVuln> candidateConfirmed = new ArrayList<>();
        List<SuspectedVuln> suspected = new ArrayList<>();
        List<String> preReasons = new ArrayList<>();

        for (JsonElement el : args.getAsJsonArray("findings")) {
            if (!el.isJsonObject()) continue;
            JsonObject f = el.getAsJsonObject();
            String type = strOr(f, "type", "");
            String title = strOr(f, "title", "");
            String verifyCommand = strOr(f, "verify_command", "");
            String payloadUsed = strOr(f, "payload_used", "");
            String identityProof = strOr(f, "identity_proof", "");
            int citedIdx = intOr(f, "cited_execution_index", -1);

            // Collect submitted evidence slots from the evidence object, plus
            // the top-level convenience fields payload_used / identity_proof.
            EnumSet<EvidenceField> submitted = EnumSet.noneOf(EvidenceField.class);
            Map<String, String> evMap = new LinkedHashMap<>();
            if (f.has("evidence") && f.get("evidence").isJsonObject()) {
                for (Map.Entry<String, JsonElement> e : f.getAsJsonObject("evidence").entrySet()) {
                    if (e.getValue() == null || e.getValue().isJsonNull()) continue;
                    String val = e.getValue().isJsonPrimitive() ? e.getValue().getAsString() : e.getValue().toString();
                    if (val == null || val.isBlank()) continue;
                    evMap.put(e.getKey(), val);
                    EvidenceField field = EvidenceField.fromKey(e.getKey());
                    if (field != null) submitted.add(field);
                }
            }
            if (!payloadUsed.isBlank()) submitted.add(EvidenceField.PAYLOAD_USED);
            if (!identityProof.isBlank()) submitted.add(EvidenceField.IDENTITY_PROOF);

            List<EvidenceField> missing = EvidenceSchema.missingRequired(type, submitted);
            if (!missing.isEmpty()) {
                suspected.add(new SuspectedVuln(type, title,
                        "证据结构不完整（缺少 " + EvidenceSchema.describe(missing) + "），已降级为疑似",
                        verifyCommand, "MEDIUM", "", payloadUsed));
                preReasons.add("证据结构校验失败: '" + title + "' 缺少必需证据 " + EvidenceSchema.describe(missing));
                continue;
            }

            // Complete (or uncovered type) → hand to VerdictValidator. Pick a
            // response slot for the "cited response ties to a real response"
            // check: explicit response, else the injected/session-B/reflected slot.
            String response = firstNonBlank(strOr(f, "response", ""),
                    evMap.get("injected_response"), evMap.get("session_b_response"),
                    evMap.get("reflected_payload"), evMap.get("canary_response"));
            String evidence = evMap.isEmpty() ? strOr(f, "evidence_text", "")
                    : String.join("\n", evMap.values());
            candidateConfirmed.add(new ConfirmedVuln(type, title, evidence, payloadUsed,
                    response, verifyCommand, identityProof, strOr(f, "cvss", ""), citedIdx));
        }

        // Layer 2: authenticity cross-checks. requireAnomaly=false — external
        // requests carry no baseline diff, so the bar is "was this payload
        // actually present in the supplied requests" (same as Agent mode).
        FinalVerdict v = VerdictValidator.validate(
                overallRisk.isBlank() ? "LOW" : overallRisk, candidateConfirmed, suspected,
                summary, recommendations, 0, payloads, false, null);

        // Merge layer-1 reasons ahead of layer-2 reasons.
        List<String> allReasons = new ArrayList<>(preReasons);
        if (v.rejectionReasons() != null) allReasons.addAll(v.rejectionReasons());
        FinalVerdict merged = new FinalVerdict(v.overallRisk(), v.confirmedVulns(),
                v.suspectedVulns(), v.summary(), v.recommendations(), 0, allReasons);

        // Default ON: an external verdict that can be tied to a path should
        // show up in the plugin's API table like any internal analysis.
        boolean persist = boolOr(args, "persist", true);
        boolean persisted = false;
        if (persist && path != null && !path.isBlank()) {
            persisted = persistVerdict(path, merged, payloads);
        }

        JsonObject out = verdictToJson(merged);
        out.addProperty("schemaChecked", true);
        if (path != null && !path.isBlank()) out.addProperty("path", path);
        out.addProperty("persisted", persisted);
        return ToolResult.ok(out.toString());
    }

    /** Write the validated verdict back to the endpoint's status (visible in
     *  the API table). Low-coupling: mirrors PipelineFacade's status mapping
     *  via the repository's public updateStatus. Returns false when the path
     *  is unknown or the write fails. */
    /** Extract the HTTP method (first request-line token) from a raw request. */
    private static String httpMethodOf(PayloadResult p) {
        if (p == null) return null;
        String req = p.sentRequest();
        if (req == null || req.isBlank()) return null;
        String firstLine = req.split("\r?\n", 2)[0].trim();
        int sp = firstLine.indexOf(' ');
        return sp > 0 ? firstLine.substring(0, sp).trim() : null;
    }

    private boolean persistVerdict(String path, FinalVerdict v, List<PayloadResult> payloads) {
        try {
            // Mutate the entry directly (via findByPath) rather than
            // repository.updateStatus(path, …): the latter keys its index by
            // method+path and silently no-ops on a path-only key, so it can't
            // be relied on here where we only have the path.
            // Auto-create an entry for endpoints the external brain discovered
            // outside API-Sentinel's proxy (they never flowed through our HTTP
            // handler, so findByPath misses). This is what makes external-brain
            // findings visible in the API table at all.
            ApiEntry entry = repository.findByPath(path).orElse(null);
            if (entry == null) {
                String method = payloads != null && !payloads.isEmpty()
                        ? httpMethodOf(payloads.get(0)) : "GET";
                entry = new ApiEntry(method == null || method.isBlank() ? "GET" : method, path);
                repository.add(entry);   // fires change -> table refresh
            }
            boolean hasConfirmed = v.confirmedVulns() != null && !v.confirmedVulns().isEmpty();
            boolean hasSuspected = v.suspectedVulns() != null && !v.suspectedVulns().isEmpty();

            // Build a first-class AnalysisRecord so the external verdict shows
            // up in the analysis-history dropdown + verdict cards just like an
            // internal Pipeline/Agent run — otherwise the external brain's
            // validated conclusions are invisible in the plugin UI.
            AnalysisResult traffic = new AnalysisResult(
                    List.of(), "", AnalysisResult.RiskLevel.NONE, 0, 0, "external-mcp", null);
            PipelineResult pr = new PipelineResult(
                    traffic, "", List.of(),
                    payloads != null ? payloads : List.of(),
                    v, Map.of());
            AnalysisRecord record = new AnalysisRecord("MCP", traffic);
            record = record.withPipelineResult(pr);
            entry.addAnalysisRecord(record);

            if (hasConfirmed) {
                String title = v.confirmedVulns().get(0).title();
                entry.updateStatus(ApiStatus.VULNERABLE, VulnType.GENERIC,
                        (title == null || title.isBlank()) ? "外部 AI 确认漏洞（validate_findings）" : title);
            } else if (hasSuspected) {
                entry.updateStatus(ApiStatus.PENDING_REVIEW, null,
                        "外部 AI 分析发现疑似漏洞，待人工确认（validate_findings）");
            } else {
                entry.updateStatus(ApiStatus.PASSED, null,
                        "外部 AI 分析未发现漏洞（validate_findings）");
            }
            repository.save();
            if (onUiRefresh != null) onUiRefresh.run();
            return true;
        } catch (Exception e) {
            if (logger != null) logger.warn("[MCP] validate_findings persist failed: %s", e.getMessage());
            return false;
        }
    }

    private JsonObject validateFindingsSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        props.add("path", strProp("optional: API path to associate/persist the verdict to"));
        props.add("overall_risk", strProp("overall risk claim: HIGH/MEDIUM/LOW/SAFE (validator may downgrade)"));
        props.add("summary", strProp("optional analysis summary"));
        props.add("recommendations", strProp("optional remediation notes"));

        // findings[]
        JsonObject findings = new JsonObject();
        findings.addProperty("type", "array");
        findings.addProperty("description", "candidate findings to validate");
        JsonObject fItem = new JsonObject();
        fItem.addProperty("type", "object");
        JsonObject fProps = new JsonObject();
        fProps.add("type", strProp("vuln type, e.g. SQL Injection / IDOR / SSRF / XSS / Command Injection"));
        fProps.add("title", strProp("short title"));
        fProps.add("cited_execution_index", intProp("index into requests[] whose payload backs this finding"));
        fProps.add("payload_used", strProp("the payload that triggered it (also counts as the payload_used evidence slot)"));
        fProps.add("identity_proof", strProp("auth-class only: which session, anonymous test, how data proven to belong to another account"));
        fProps.add("response", strProp("optional: response snippet that must appear verbatim in a real received_response"));
        fProps.add("cvss", strProp("optional CVSS vector"));
        fProps.add("verify_command", strProp("optional reproduction steps"));
        JsonObject evidence = new JsonObject();
        evidence.addProperty("type", "object");
        evidence.addProperty("description", "evidence slots keyed by name: baseline_response, injected_response, "
                + "response_diff, error_message, timing_evidence, session_a_response, session_b_response, "
                + "anonymous_response, internal_indicator, reflected_payload, encoding_test, canary_response");
        fProps.add("evidence", evidence);
        fItem.add("properties", fProps);
        JsonArray fReq = new JsonArray();
        fReq.add("type"); fReq.add("title");
        fItem.add("required", fReq);
        findings.add("items", fItem);
        props.add("findings", findings);

        // requests[]
        JsonObject requests = new JsonObject();
        requests.addProperty("type", "array");
        requests.addProperty("description", "request/response records that back the findings");
        JsonObject rItem = new JsonObject();
        rItem.addProperty("type", "object");
        JsonObject rProps = new JsonObject();
        rProps.add("execution_index", intProp("index referenced by findings[].cited_execution_index"));
        rProps.add("sent_request", strProp("raw HTTP request (request line lets the validator recover the path)"));
        rProps.add("received_response", strProp("raw HTTP response"));
        rProps.add("status_code", intProp("HTTP status code"));
        rProps.add("anomaly_detected", boolProp("whether this request showed anomalous behaviour"));
        rProps.add("auth_session", strProp("session label (e.g. alice/bob) — required for auth-class two-session checks"));
        rItem.add("properties", rProps);
        requests.add("items", rItem);
        props.add("requests", requests);

        props.add("persist", boolProp("optional: when true and path is set, write the verdict to the endpoint's status"));

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("findings");
        schema.add("required", required);
        return schema;
    }

    private static JsonObject strProp(String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", "string");
        p.addProperty("description", desc);
        return p;
    }

    private static JsonObject intProp(String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", "integer");
        p.addProperty("description", desc);
        return p;
    }

    private static JsonObject boolProp(String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", "boolean");
        p.addProperty("description", desc);
        return p;
    }

    // ======================== helpers ========================

    private ApiEntry requireEntry(JsonObject args) {
        String path = str(args, "path");
        if (path == null || path.isBlank()) return null;
        Optional<ApiEntry> opt = repository.findByPath(path);
        if (opt.isPresent()) return opt.get();
        // Fuzzy fallback: let an external brain reference an endpoint by name
        // (e.g. "getDataServicePeering") without knowing the exact full path.
        return fuzzyFindByPath(path);
    }

    /** Case-insensitive substring match on apiPath; returns the shortest (most
     *  specific) match. Null when nothing contains the query. */
    private ApiEntry fuzzyFindByPath(String query) {
        if (query == null || query.isBlank()) return null;
        String q = query.toLowerCase(Locale.ROOT);
        ApiEntry best = null;
        for (ApiEntry e : repository.findAll()) {
            String p = e.getApiPath();
            if (p != null && p.toLowerCase(Locale.ROOT).contains(q)) {
                if (best == null || p.length() < best.getApiPath().length()) best = e;
            }
        }
        return best;
    }

    private static String str(JsonObject args, String key) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return null;
        return args.get(key).getAsString();
    }

    private static String strOr(JsonObject args, String key, String def) {
        String v = str(args, key);
        return v == null ? def : v;
    }

    private static int intOr(JsonObject args, String key, int def) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return def;
        try {
            return args.get(key).getAsInt();
        } catch (RuntimeException e) {
            return def;
        }
    }

    private static boolean boolOr(JsonObject args, String key, boolean def) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return def;
        try {
            return args.get(key).getAsBoolean();
        } catch (RuntimeException e) {
            return def;
        }
    }

    /** First non-blank string among the arguments, or "" when all blank/null. */
    private static String firstNonBlank(String... values) {
        if (values == null) return "";
        for (String v : values) {
            if (v != null && !v.isBlank()) return v;
        }
        return "";
    }

    private static LinkedHashMap<String, String> props(String... kv) {
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) map.put(kv[i], kv[i + 1]);
        return map;
    }

    static JsonObject verdictToJson(FinalVerdict v) {
        JsonObject o = new JsonObject();
        o.addProperty("overallRisk", v.overallRisk());
        JsonArray confirmed = new JsonArray();
        if (v.confirmedVulns() != null) {
            for (ConfirmedVuln c : v.confirmedVulns()) {
                JsonObject c_o = new JsonObject();
                c_o.addProperty("type", c.type());
                c_o.addProperty("title", c.title());
                c_o.addProperty("evidence", c.evidence());
                c_o.addProperty("payloadUsed", c.payloadUsed());
                if (c.cvss() != null && !c.cvss().isBlank()) c_o.addProperty("cvss", c.cvss());
                confirmed.add(c_o);
            }
        }
        o.add("confirmedVulns", confirmed);
        JsonArray suspected = new JsonArray();
        if (v.suspectedVulns() != null) {
            for (SuspectedVuln s : v.suspectedVulns()) {
                JsonObject s_o = new JsonObject();
                s_o.addProperty("type", s.type());
                s_o.addProperty("title", s.title());
                s_o.addProperty("reason", s.reason());
                s_o.addProperty("confidence", s.confidence());
                suspected.add(s_o);
            }
        }
        o.add("suspectedVulns", suspected);
        o.addProperty("summary", v.summary());
        o.addProperty("recommendations", v.recommendations());
        if (v.rejectionReasons() != null && !v.rejectionReasons().isEmpty()) {
            JsonArray rr = new JsonArray();
            v.rejectionReasons().forEach(rr::add);
            o.add("rejectionReasons", rr);
        }
        return o;
    }
}
