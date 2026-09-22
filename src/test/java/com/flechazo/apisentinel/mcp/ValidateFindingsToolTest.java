package com.flechazo.apisentinel.mcp;

import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.repository.InMemoryApiRepository;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for the two-layer validate_findings MCP tool (EvidenceSchema + VerdictValidator). */
class ValidateFindingsToolTest {

    private McpTools newTools(InMemoryApiRepository repo) {
        LeveledLogger logger = new LeveledLogger(null);
        return new McpTools(repo, new LlmProviderFactory(),
                new ConfigManager(logger), new CodeIndexService(logger), logger);
    }

    private JsonObject call(McpTools tools, String json) {
        McpTools.ToolResult r = tools.callTool("validate_findings",
                JsonParser.parseString(json).getAsJsonObject());
        assertFalse(r.isError(), "tool returned error: " + r.text());
        return JsonParser.parseString(r.text()).getAsJsonObject();
    }

    /** Two requests from different sessions on the same path; cited response
     *  appears verbatim in a real received_response. */
    private static final String IDOR_REQUESTS = """
            "requests": [
              {"execution_index":0,"auth_session":"alice",
               "sent_request":"GET /api/order/detail?id=1001 HTTP/1.1\\r\\n\\r\\n",
               "received_response":"HTTP/1.1 200 OK\\r\\n\\r\\n{\\"userId\\":1,\\"owner\\":\\"alice\\"}"},
              {"execution_index":1,"auth_session":"bob","anomaly_detected":true,
               "sent_request":"GET /api/order/detail?id=1001 HTTP/1.1\\r\\n\\r\\n",
               "received_response":"HTTP/1.1 200 OK\\r\\n\\r\\n{\\"userId\\":1,\\"owner\\":\\"alice\\"}"}
            ]""";

    @Test
    void idorComplete_survivesBothLayers() {
        McpTools tools = newTools(new InMemoryApiRepository());
        String json = "{"
                + "\"overall_risk\":\"HIGH\","
                + "\"findings\":[{"
                + "  \"type\":\"IDOR\",\"title\":\"订单越权\",\"cited_execution_index\":1,"
                + "  \"identity_proof\":\"bob 会话读到 alice 的订单，owner=alice 非本人\","
                + "  \"evidence\":{"
                + "     \"session_a_response\":\"alice sees own order\","
                + "     \"session_b_response\":\"{\\\"userId\\\":1,\\\"owner\\\":\\\"alice\\\"}\","
                + "     \"anonymous_response\":\"401 Unauthorized\"}"
                + "}],"
                + IDOR_REQUESTS
                + "}";
        JsonObject out = call(tools, json);
        JsonArray confirmed = out.getAsJsonArray("confirmedVulns");
        assertEquals(1, confirmed.size(), "complete IDOR should survive; got: " + out);
        assertEquals("HIGH", out.get("overallRisk").getAsString());
    }

    @Test
    void idorMissingIdentityProof_demotedBySchema() {
        McpTools tools = newTools(new InMemoryApiRepository());
        String json = "{"
                + "\"overall_risk\":\"HIGH\","
                + "\"findings\":[{"
                + "  \"type\":\"IDOR\",\"title\":\"订单越权\",\"cited_execution_index\":1,"
                + "  \"evidence\":{"
                + "     \"session_a_response\":\"a\",\"session_b_response\":\"b\",\"anonymous_response\":\"401\"}"
                + "}],"
                + IDOR_REQUESTS
                + "}";
        JsonObject out = call(tools, json);
        assertEquals(0, out.getAsJsonArray("confirmedVulns").size());
        assertTrue(out.getAsJsonArray("suspectedVulns").size() >= 1);
        String reasons = out.getAsJsonArray("rejectionReasons").toString();
        assertTrue(reasons.contains("证据结构校验失败"), reasons);
        assertTrue(reasons.contains("identity_proof"), reasons);
        // HIGH with no surviving confirmed → downgraded by VerdictValidator.
        assertNotEquals("HIGH", out.get("overallRisk").getAsString());
    }

    @Test
    void sqliMissingBaseline_demotedBySchema() {
        McpTools tools = newTools(new InMemoryApiRepository());
        String json = "{"
                + "\"findings\":[{"
                + "  \"type\":\"SQL Injection\",\"title\":\"id 参数注入\",\"payload_used\":\"' OR 1=1--\","
                + "  \"evidence\":{"
                + "     \"injected_response\":\"error near\",\"response_diff\":\"differs\"}"
                + "}]"
                + "}";
        JsonObject out = call(tools, json);
        assertEquals(0, out.getAsJsonArray("confirmedVulns").size());
        String reasons = out.getAsJsonArray("rejectionReasons").toString();
        assertTrue(reasons.contains("baseline_response"), reasons);
    }

    @Test
    void uncoveredType_failsOpen_noSchemaRejection() {
        McpTools tools = newTools(new InMemoryApiRepository());
        String json = "{"
                + "\"findings\":[{"
                + "  \"type\":\"CSRF\",\"title\":\"无 CSRF token\",\"payload_used\":\"whatever\"}]"
                + "}";
        JsonObject out = call(tools, json);
        // The schema layer must not gate an uncovered type.
        JsonArray rr = out.has("rejectionReasons") ? out.getAsJsonArray("rejectionReasons") : new JsonArray();
        assertFalse(rr.toString().contains("证据结构校验失败"),
                "uncovered type should not be schema-gated: " + rr);
    }

    @Test
    void missingFindings_isError() {
        McpTools tools = newTools(new InMemoryApiRepository());
        McpTools.ToolResult r = tools.callTool("validate_findings", new JsonObject());
        assertTrue(r.isError());
        assertTrue(r.text().contains("findings"));
    }

    @Test
    void persist_writesVerdictToEntryStatus() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        repo.add(new ApiEntry("GET", "/api/order/detail"));
        McpTools tools = newTools(repo);
        String json = "{"
                + "\"path\":\"/api/order/detail\",\"persist\":true,\"overall_risk\":\"HIGH\","
                + "\"findings\":[{"
                + "  \"type\":\"IDOR\",\"title\":\"订单越权\",\"cited_execution_index\":1,"
                + "  \"identity_proof\":\"bob 读到 alice 数据\","
                + "  \"evidence\":{"
                + "     \"session_a_response\":\"a\","
                + "     \"session_b_response\":\"{\\\"userId\\\":1,\\\"owner\\\":\\\"alice\\\"}\","
                + "     \"anonymous_response\":\"401\"}"
                + "}],"
                + IDOR_REQUESTS
                + "}";
        JsonObject out = call(tools, json);
        assertTrue(out.get("persisted").getAsBoolean(), "should persist: " + out);
        assertEquals(ApiStatus.VULNERABLE, repo.findByPath("/api/order/detail").orElseThrow().getStatus());
    }

    @Test
    void persist_unknownPath_autoCreatesEntry() {
        // Endpoints the external brain discovered outside API-Sentinel's proxy
        // don't exist in the repository yet. validate_findings now auto-creates
        // an entry so the verdict shows up in the API table (the core sync fix).
        InMemoryApiRepository repo = new InMemoryApiRepository();
        McpTools tools = newTools(repo);
        String json = "{"
                + "\"path\":\"/nope\",\"persist\":true,"
                + "\"findings\":[{\"type\":\"CSRF\",\"title\":\"x\"}]"
                + "}";
        JsonObject out = call(tools, json);
        assertTrue(out.get("persisted").getAsBoolean(), "should auto-create + persist: " + out);
        assertTrue(repo.findByPath("/nope").isPresent(), "entry should be auto-created");
    }
}
