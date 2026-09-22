package com.flechazo.apisentinel.mcp;

import com.flechazo.apisentinel.ai.pipeline.ConfirmedVuln;
import com.flechazo.apisentinel.ai.pipeline.FinalVerdict;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.repository.InMemoryApiRepository;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for the MCP tool surface (read-only tools + dispatch + verdict JSON). */
class McpToolsTest {

    private McpTools newTools(InMemoryApiRepository repo) {
        LeveledLogger logger = new LeveledLogger(null);
        return new McpTools(repo, new LlmProviderFactory(),
                new ConfigManager(logger), new CodeIndexService(logger), logger);
    }

    @Test
    void listTools_advertisesAllTools() {
        LeveledLogger logger = new LeveledLogger(null);
        ConfigManager cm = new ConfigManager(logger);
        // Deterministic: set in-memory (AppConfig setter, no disk write) so the
        // test doesn't depend on the developer's ambient saved config.
        cm.getConfig().setMcpAllowActiveTools(false);
        McpTools tools = new McpTools(new InMemoryApiRepository(), new LlmProviderFactory(),
                cm, new CodeIndexService(logger), logger);

        Set<String> names = tools.listTools().stream()
                .map(McpProtocol.ToolDef::name).collect(Collectors.toSet());
        // Native curated tools are always advertised.
        assertTrue(names.containsAll(Set.of("list_apis", "get_api_detail", "get_passive_findings",
                        "get_analysis_history", "analyze_api", "search_code", "get_source_code",
                        "analyze_batch", "get_untracked_apis", "get_latest_events", "validate_findings",
                        "ingest_traffic", "audit_codebase", "read_file", "trace_taint_source",
                        "find_definition", "find_callers", "map_sibling_endpoints",
                        "browser_discover", "browser_dom_xss", "browser_render")),
                "native tools missing: " + names);
        // The session registry adds the wider agent toolset (read-only ones
        // available even without provider/browser).
        assertTrue(names.contains("search_source_code"), "registry tools should merge in: " + names);
        // Active/dangerous tools are gated off when mcpAllowActiveTools=false.
        assertFalse(names.contains("send_request"), "active tools must be gated: " + names);
        assertFalse(names.contains("run_sandboxed_code"), "active tools must be gated: " + names);

        // Flip the gate on (in-memory) → active tools now advertised.
        cm.getConfig().setMcpAllowActiveTools(true);
        Set<String> gatedOpen = tools.listTools().stream()
                .map(McpProtocol.ToolDef::name).collect(Collectors.toSet());
        assertTrue(gatedOpen.contains("send_request"), "active tools should appear when allowed: " + gatedOpen);
    }

    @Test
    void ingestTraffic_createsEntryVisibleInTable() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        McpTools tools = newTools(repo);
        JsonObject args = new JsonObject();
        args.addProperty("path", "/api/ext/discovered");
        args.addProperty("method", "POST");
        args.addProperty("domain", "ext.example.com");
        args.addProperty("request", "POST /api/ext/discovered HTTP/1.1\r\nHost: ext.example.com\r\n\r\n");
        McpTools.ToolResult r = tools.callTool("ingest_traffic", args);
        assertFalse(r.isError(), r.text());
        JsonObject out = JsonParser.parseString(r.text()).getAsJsonObject();
        assertTrue(out.get("created").getAsBoolean());
        assertTrue(out.get("hasTraffic").getAsBoolean());
        // The endpoint the external brain discovered is now in the repository.
        ApiEntry e = repo.findByPath("/api/ext/discovered").orElseThrow();
        assertEquals("POST", e.getHttpMethod());
        assertEquals("ext.example.com", e.getDomain());
    }

    @Test
    void ingestTraffic_updatesExistingEntry() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        ApiEntry e = new ApiEntry("GET", "/api/x"); repo.add(e);
        McpTools tools = newTools(repo);
        JsonObject args = new JsonObject();
        args.addProperty("path", "/api/x");
        args.addProperty("domain", "x.com");
        McpTools.ToolResult r = tools.callTool("ingest_traffic", args);
        JsonObject out = JsonParser.parseString(r.text()).getAsJsonObject();
        assertTrue(out.get("updated").getAsBoolean());
        assertEquals("x.com", repo.findByPath("/api/x").orElseThrow().getDomain());
    }

    @Test
    void callTool_unknownTool_isError() {
        McpTools tools = newTools(new InMemoryApiRepository());
        McpTools.ToolResult r = tools.callTool("nope", new JsonObject());
        assertTrue(r.isError());
        assertTrue(r.text().contains("Unknown tool"));
    }

    @Test
    void listApis_returnsRepositoryEntries() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        ApiEntry e = new ApiEntry("GET", "/api/users/{id}");
        e.setDomain("example.com");
        repo.add(e);

        McpTools tools = newTools(repo);
        JsonObject args = new JsonObject();
        McpTools.ToolResult r = tools.callTool("list_apis", args);
        assertFalse(r.isError());
        JsonObject out = JsonParser.parseString(r.text()).getAsJsonObject();
        assertEquals(1, out.get("count").getAsInt());
        assertEquals("/api/users/{id}",
                out.getAsJsonArray("apis").get(0).getAsJsonObject().get("path").getAsString());
    }

    @Test
    void listApis_filterByDomain() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        ApiEntry a = new ApiEntry("GET", "/a"); a.setDomain("a.com"); repo.add(a);
        ApiEntry b = new ApiEntry("GET", "/b"); b.setDomain("b.com"); repo.add(b);

        McpTools tools = newTools(repo);
        JsonObject args = new JsonObject();
        args.addProperty("domain", "a.com");
        McpTools.ToolResult r = tools.callTool("list_apis", args);
        JsonObject out = JsonParser.parseString(r.text()).getAsJsonObject();
        assertEquals(1, out.get("count").getAsInt());
    }

    @Test
    void getApiDetail_notFound_isError() {
        McpTools tools = newTools(new InMemoryApiRepository());
        JsonObject args = new JsonObject();
        args.addProperty("path", "/missing");
        McpTools.ToolResult r = tools.callTool("get_api_detail", args);
        assertTrue(r.isError());
        assertTrue(r.text().contains("not found"));
    }

    @Test
    void getApiDetail_found_returnsMeta() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        ApiEntry e = new ApiEntry("POST", "/api/login");
        e.setDomain("example.com");
        repo.add(e);

        McpTools tools = newTools(repo);
        JsonObject args = new JsonObject();
        args.addProperty("path", "/api/login");
        McpTools.ToolResult r = tools.callTool("get_api_detail", args);
        assertFalse(r.isError());
        JsonObject out = JsonParser.parseString(r.text()).getAsJsonObject();
        assertEquals("POST", out.get("method").getAsString());
        assertEquals("/api/login", out.get("path").getAsString());
    }

    @Test
    void analyzeApi_noProvider_isError() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        ApiEntry e = new ApiEntry("GET", "/api/x"); repo.add(e);
        McpTools tools = newTools(repo);
        // No analysis triggers set and no provider configured → graceful error.
        JsonObject args = new JsonObject();
        args.addProperty("path", "/api/x");
        McpTools.ToolResult r = tools.callTool("analyze_api", args);
        assertTrue(r.isError());
    }

    @Test
    void verdictToJson_includesRiskAndFindings() {
        FinalVerdict v = new FinalVerdict("HIGH",
                List.of(new ConfirmedVuln("SQLi", "SQL 注入", "报错回显", "payload",
                        "resp", "curl", "身份证据", "8.8")),
                List.of(), "发现SQL注入", "修复", 100, List.of("reason1"));
        JsonObject o = McpTools.verdictToJson(v);
        assertEquals("HIGH", o.get("overallRisk").getAsString());
        assertEquals(1, o.getAsJsonArray("confirmedVulns").size());
        assertEquals("SQLi", o.getAsJsonArray("confirmedVulns")
                .get(0).getAsJsonObject().get("type").getAsString());
        assertEquals("8.8", o.getAsJsonArray("confirmedVulns")
                .get(0).getAsJsonObject().get("cvss").getAsString());
        assertEquals("reason1", o.getAsJsonArray("rejectionReasons").get(0).getAsString());
    }
}
