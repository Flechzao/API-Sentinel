package com.flechazo.apisentinel.mcp;

import com.flechazo.apisentinel.ai.agent.FindingEvidenceStore;
import com.flechazo.apisentinel.ai.agent.ProgressiveToolDisclosure;
import com.flechazo.apisentinel.ai.agent.tool.AgentToolRegistry;
import com.flechazo.apisentinel.ai.agent.tool.ToolContext;

/**
 * Per-MCP-session state, keyed by {@code Mcp-Session-Id}. Gives an external
 * brain the same stateful footing the built-in Agent loop has: a persistent
 * {@link ToolContext} (session cookies, request-sending, a live browser page),
 * a {@link FindingEvidenceStore} for analysis notes, and a
 * {@link ProgressiveToolDisclosure} so {@code request_tools} + phased tools work
 * across multiple {@code tools/call} round-trips.
 *
 * <p>The persistent stores ({@link #findingStore}, {@link #disclosure}) survive
 * even when the {@link ToolContext} + {@link AgentToolRegistry} are rebuilt for a
 * new target endpoint (tools capture their context at construction, so switching
 * the focused {@link com.flechazo.apisentinel.model.ApiEntry} requires a fresh
 * registry — but the notes and the browser session must not be lost).
 *
 * <p>Not thread-safe on its own: {@link McpTools} serializes {@code tools/call}
 * per session via {@link #lock}, so a single session never runs two tool calls
 * concurrently (different sessions still run in parallel).
 */
final class McpSession {

    final String id;
    /** Serializes tool calls within this session (cross-session stays parallel). */
    final Object lock = new Object();

    /** Persistent across ToolContext rebuilds — must outlive endpoint switches. */
    final FindingEvidenceStore findingStore;
    final ProgressiveToolDisclosure disclosure;

    /** The endpoint the current {@link #ctx}/{@link #registry} are bound to
     *  (null = no specific endpoint / general query session). */
    volatile String currentPath;
    volatile ToolContext ctx;
    volatile AgentToolRegistry registry;
    /** Full build result — kept so we can harvest the shared SendRequestTool's
     *  accumulated PayloadResults (every request-sending tool routes through it)
     *  and persist them into the endpoint's test-case list. */
    volatile com.flechazo.apisentinel.ai.agent.tool.StandardToolRegistry.Tools tools;

    /** One reusable "MCP" analysis record per endpoint path, updated in place
     *  (remove+add) as more requests are sent — so sent traffic shows up in the
     *  Repeater's 测试用例列表 without spamming the analysis history. */
    final java.util.Map<String, com.flechazo.apisentinel.model.AnalysisRecord> trafficRecordByPath =
            new java.util.concurrent.ConcurrentHashMap<>();

    volatile long lastAccess;

    McpSession(String id, FindingEvidenceStore findingStore, ProgressiveToolDisclosure disclosure) {
        this.id = id;
        this.findingStore = findingStore;
        this.disclosure = disclosure;
        this.lastAccess = System.currentTimeMillis();
    }

    void touch() { this.lastAccess = System.currentTimeMillis(); }
}
