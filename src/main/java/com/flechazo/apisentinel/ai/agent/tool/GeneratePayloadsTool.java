package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.testgen.TestCaseService;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class GeneratePayloadsTool implements AgentTool {

    private final ToolContext ctx;
    private final List<VulnFinding> knownFindings = new ArrayList<>();
    // Cumulative across every generate_payloads call in this analysis — the
    // Agent may call this tool multiple times as findings evolve, and the
    // final report/Repeater view need the full history, not just the last
    // batch. lastBatchCases (below) is the per-call scratch list used only
    // to build this call's own JSON response to the LLM.
    private final List<TestCase> allGeneratedCases = new ArrayList<>();
    private List<TestCase> lastBatchCases = new ArrayList<>();

    public GeneratePayloadsTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    public void addFindings(List<VulnFinding> findings) {
        if (findings != null) knownFindings.addAll(findings);
    }

    public List<TestCase> getGeneratedCases() { return allGeneratedCases; }

    @Override
    public String preExecute(String argumentsJson, ToolContext ctx) {
        // Check if there are any findings to base payloads on
        if (knownFindings.isEmpty()) {
            ctx.logger().info("[generate_payloads] No findings available — "
                    + "payloads will be generated without specific vulnerability clues. "
                    + "Consider calling analyze_traffic or heuristic_scan first.");
        }
        return null; // allow — payloads can still be generated speculatively
    }

    @Override
    public void postExecute(String argumentsJson, String result, ToolContext ctx) {
        // Update the session state so submit_report can enforce the verify gate
        ctx.sessionState().setGeneratedPayloadCount(allGeneratedCases.size());

        if (!lastBatchCases.isEmpty() && ctx.logger() != null) {
            ctx.logger().info("[generate_payloads] Generated %d test cases (total: %d)",
                    lastBatchCases.size(), allGeneratedCases.size());
        }
    }

    @Override
    public String name() { return "generate_payloads"; }

    @Override
    public String description() {
        return "Generate targeted security test payloads based on discovered vulnerabilities. "
             + "Creates test cases with specific HTTP requests designed to verify suspected issues. "
             + "Uses findings from analyze_traffic and heuristic_scan to focus payload generation. "
             + "Costs 1 LLM call.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        JsonObject focusProp = new JsonObject();
        focusProp.addProperty("type", "string");
        focusProp.addProperty("description", "Vulnerability types to focus on, comma-separated (e.g. 'SQL Injection,XSS'). Optional.");
        props.add("focus", focusProp);
        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        var entry = ctx.entry();
        // Cost tiering: payload generation is enumerative — route it to the
        // low-cost model when tiering is enabled (bad payloads are caught by the
        // downstream verification/anti-hallucination gate).
        TestCaseService service = new TestCaseService(ctx.provider(), ctx.logger(), ctx.cheapModelOverride());

        String method = entry.getHttpMethod() != null ? entry.getHttpMethod() : "GET";
        String path = entry.getApiPath();
        String host = entry.getDomain() != null ? entry.getDomain() : "";

        String params = "";
        String lastUrl = entry.getLastUrl();
        if (lastUrl != null && lastUrl.contains("?")) {
            params = "Query: " + lastUrl.substring(lastUrl.indexOf('?') + 1);
        }
        String rawReq = entry.getLastRawRequest();
        if (rawReq != null) {
            int bodyStart = rawReq.indexOf("\r\n\r\n");
            if (bodyStart < 0) bodyStart = rawReq.indexOf("\n\n");
            if (bodyStart >= 0) {
                String body = rawReq.substring(bodyStart).trim();
                if (!body.isEmpty()) {
                    if (!params.isEmpty()) params += "; ";
                    params += "Body: " + (body.length() > 500 ? body.substring(0, 500) : body);
                }
            }
        }

        try {
            var result = service.generateDetailed(method, path, host, params, "", knownFindings)
                    .get(600, TimeUnit.SECONDS);

            lastBatchCases = new ArrayList<>();
            if (result.cases() != null) lastBatchCases.addAll(result.cases());
            allGeneratedCases.addAll(lastBatchCases);

            JsonObject out = new JsonObject();
            out.addProperty("success", !lastBatchCases.isEmpty());
            out.addProperty("count", lastBatchCases.size());
            if (result.reasoning() != null) {
                out.addProperty("reasoning", result.reasoning());
            }

            JsonArray casesArr = new JsonArray();
            for (TestCase tc : lastBatchCases) {
                JsonObject co = new JsonObject();
                co.addProperty("name", tc.name());
                co.addProperty("category", tc.category());
                co.addProperty("target_param", tc.targetParam());
                co.addProperty("method", tc.method());
                co.addProperty("path", tc.path());
                co.addProperty("payload", tc.payload());
                co.addProperty("description", tc.description());
                co.addProperty("expected_if_vulnerable", tc.expectedIfVulnerable());
                casesArr.add(co);
            }
            out.add("test_cases", casesArr);
            out.addProperty("next_step", "建议: 已生成 " + lastBatchCases.size()
                    + " 个测试用例，调用 send_request 逐个发送验证。优先验证最可能触发漏洞的 payload");
            return out.toString();
        } catch (Exception e) {
            return "{\"success\": false, \"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
