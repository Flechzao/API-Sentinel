package com.flechazo.apisentinel.mcp;

import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.pipeline.SuspectedVuln;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.codeindex.RepoGrepper;
import com.flechazo.apisentinel.codeindex.parser.RouteEntry;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.PassiveFinding;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.google.gson.JsonArray;
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

    // ======================== tool registry ========================

    public List<McpProtocol.ToolDef> listTools() {
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

        return tools;
    }

    public ToolResult callTool(String name, JsonObject args) {
        try {
            return switch (name == null ? "" : name) {
                case "list_apis" -> listApis(args);
                case "get_api_detail" -> getApiDetail(args);
                case "get_passive_findings" -> getPassiveFindings(args);
                case "get_analysis_history" -> getAnalysisHistory(args);
                case "analyze_api" -> analyzeApi(args);
                case "search_code" -> searchCode(args);
                case "get_source_code" -> getSourceCode(args);
                case "analyze_batch" -> analyzeBatch(args);
                case "get_untracked_apis" -> getUntrackedApis(args);
                case "get_latest_events" -> getLatestEvents();
                default -> ToolResult.error("Unknown tool: " + name);
            };
        } catch (Exception e) {
            if (logger != null) logger.warn("[MCP] tool '%s' failed: %s", name, e.getMessage());
            return ToolResult.error("Tool error: " + e.getMessage());
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
        List<RepoGrepper.GrepMatch> matches;
        try {
            matches = RepoGrepper.search(repos, Pattern.compile(keyword), null, 50, 1);
        } catch (Exception e) {
            return ToolResult.error("Invalid regex: " + e.getMessage());
        }
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

    // ======================== helpers ========================

    private ApiEntry requireEntry(JsonObject args) {
        String path = str(args, "path");
        if (path == null || path.isBlank()) return null;
        Optional<ApiEntry> opt = repository.findByPath(path);
        return opt.orElse(null);
    }

    private static String str(JsonObject args, String key) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return null;
        return args.get(key).getAsString();
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
