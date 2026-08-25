package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.analysis.AnalysisResult;
import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.analysis.VulnerabilityAnalyzer;
import com.flechazo.apisentinel.util.HttpMessageUtils;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class AnalyzeTrafficTool implements AgentTool {

    /** Response headers worth surfacing to the Agent without it having to
     *  re-scan the full raw response text. */
    private static final java.util.Set<String> SECURITY_HEADERS = java.util.Set.of(
            "content-security-policy", "x-frame-options", "x-content-type-options",
            "strict-transport-security", "access-control-allow-origin",
            "access-control-allow-credentials", "set-cookie", "www-authenticate",
            "x-powered-by", "server");

    private final ToolContext ctx;
    private AnalysisResult lastResult;

    public AnalyzeTrafficTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    public AnalysisResult getLastResult() { return lastResult; }

    @Override
    public String name() { return "analyze_traffic"; }

    @Override
    public String description() {
        return "Structure the captured HTTP traffic into an easy-to-scan summary (parameters, "
             + "security-relevant headers, cookies, obvious error/leak signals) for you to analyze "
             + "yourself with the full context you already have. Default mode='format_only' is free, "
             + "no LLM call. Pass mode='full' for an independent second-opinion AI analysis pass "
             + "(costs 1 LLM call) — only worth it when you want a fresh, contextless read of the "
             + "raw traffic to cross-check your own conclusions.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        JsonObject modeProp = new JsonObject();
        modeProp.addProperty("type", "string");
        modeProp.addProperty("description", "'format_only' (default, free): structured extraction only, "
                + "no LLM call — you analyze it yourself. 'full': separate AI analysis pass, costs 1 LLM call.");
        props.add("mode", modeProp);

        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        String mode = "format_only";
        try {
            var parsed = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            if (parsed.has("mode") && !parsed.get("mode").getAsString().isBlank()) {
                mode = parsed.get("mode").getAsString();
            }
        } catch (Exception ignored) {}

        return "full".equals(mode) ? executeFullAnalysis() : executeFormatOnly();
    }

    /**
     * Free, no-LLM structured extraction of the traffic already captured on
     * the entry. The Agent already has the raw request/response in its own
     * context (buildInitialUserMessage) — this just saves it from having to
     * manually parse query/body params and headers out of raw HTTP text, and
     * flags a few obvious signals (SQL errors, stack traces, reflected input)
     * so it knows where to look first.
     */
    private String executeFormatOnly() {
        var entry = ctx.entry();
        String rawReq = entry.getLastRawRequest() != null ? entry.getLastRawRequest() : "";
        String rawResp = entry.getLastRawResponse() != null ? entry.getLastRawResponse() : "";
        int statusCode = entry.getLastStatusCode();

        JsonObject result = new JsonObject();
        result.addProperty("success", true);
        result.addProperty("mode", "format_only");
        result.addProperty("method", entry.getHttpMethod());
        result.addProperty("path", entry.getApiPath());
        result.addProperty("status_code", statusCode);

        JsonObject params = new JsonObject();
        Map<String, String> queryParams = HttpMessageUtils.parseQueryParams(HttpMessageUtils.requestTarget(rawReq));
        JsonObject queryObj = new JsonObject();
        queryParams.forEach(queryObj::addProperty);
        params.add("query", queryObj);
        String body = HttpMessageUtils.bodyOf(rawReq);
        if (body != null && !body.isBlank()) {
            params.addProperty("body_raw", truncate(body, 3000));
            var jsonBody = HttpMessageUtils.parseJsonObject(body);
            if (jsonBody != null) {
                JsonArray fields = new JsonArray();
                jsonBody.keySet().forEach(fields::add);
                params.add("body_json_fields", fields);
            }
        }
        result.add("parameters", params);

        JsonObject secHeaders = new JsonObject();
        for (String h : SECURITY_HEADERS) {
            String v = HttpMessageUtils.getHeader(rawResp, h);
            if (v != null) secHeaders.addProperty(h, v);
        }
        result.add("response_security_headers", secHeaders);

        String cookieHeader = HttpMessageUtils.getHeader(rawReq, "Cookie");
        if (cookieHeader != null) result.addProperty("request_cookies", truncate(cookieHeader, 500));

        JsonArray signals = detectSignals(rawResp, statusCode);
        result.add("security_signals", signals);

        result.addProperty("note", "结构化提取，未调用 LLM。你已经在上下文中拥有完整的原始请求/响应，"
                + "请结合已读到的源码自行分析；如需生成针对性 payload，直接调用 generate_payloads 并用 "
                + "focus 参数指明怀疑的漏洞类型。");

        // Keep downstream contract intact (AgentLoop feeds getLastResult().findings()
        // into GeneratePayloadsTool) — format_only has no LLM findings of its own;
        // the Agent should express its own conclusions via generate_payloads' focus param.
        lastResult = new AnalysisResult(List.of(), "format_only: 由 Agent 自行分析",
                AnalysisResult.RiskLevel.NONE, 0, 0, "n/a", null);

        return result.toString();
    }

    private JsonArray detectSignals(String rawResp, int statusCode) {
        JsonArray signals = new JsonArray();
        String body = HttpMessageUtils.bodyOf(rawResp);
        if (body == null) return signals;
        String lower = body.toLowerCase(Locale.ROOT);

        if (statusCode == 500 && containsAny(lower, "sql syntax", "mysql", "ora-", "postgresql",
                "sqlite", "sqlexception", "jdbc", "hibernate", "unclosed quotation")) {
            signals.add("sql_error_in_response");
        }
        if (containsAny(lower, "at java.", "at com.", "traceback (most recent call last)",
                "stack trace", "exception in thread")) {
            signals.add("stack_trace_in_response");
        }
        if (containsAny(lower, "root:x:", "/etc/passwd", "c:\\windows")) {
            signals.add("file_content_leak_suspected");
        }
        if (statusCode >= 500) {
            signals.add("server_error_" + statusCode);
        }
        return signals;
    }

    private static boolean containsAny(String haystack, String... needles) {
        for (String n : needles) if (haystack.contains(n)) return true;
        return false;
    }

    /** Legacy behaviour: a separate LLM call via VulnerabilityAnalyzer. Kept for
     *  when the Agent explicitly wants an independent second opinion. */
    private String executeFullAnalysis() {
        var entry = ctx.entry();
        VulnerabilityAnalyzer analyzer = new VulnerabilityAnalyzer(ctx.provider(), ctx.logger());

        String method = entry.getHttpMethod() != null ? entry.getHttpMethod() : "GET";
        String path = entry.getApiPath();
        String host = entry.getDomain() != null ? entry.getDomain() : "";
        String rawReq = entry.getLastRawRequest() != null ? entry.getLastRawRequest() : "";
        String rawResp = entry.getLastRawResponse() != null ? entry.getLastRawResponse() : "";
        int statusCode = entry.getLastStatusCode();

        String requestBody = "";
        int bodyStart = rawReq.indexOf("\r\n\r\n");
        if (bodyStart < 0) bodyStart = rawReq.indexOf("\n\n");
        if (bodyStart >= 0) requestBody = rawReq.substring(bodyStart).trim();

        try {
            lastResult = analyzer.analyze(method, path, host, requestBody, statusCode,
                    rawResp, path, "", "", "").get(200, TimeUnit.SECONDS);

            JsonObject result = new JsonObject();
            result.addProperty("success", lastResult.isSuccess());
            result.addProperty("mode", "full");
            result.addProperty("overall_risk", lastResult.overallRisk() != null ? lastResult.overallRisk().name() : "NONE");
            result.addProperty("summary", lastResult.summary());
            result.addProperty("findings_count", lastResult.findings().size());

            var findingsArr = new com.google.gson.JsonArray();
            for (var f : lastResult.findings()) {
                JsonObject fo = new JsonObject();
                fo.addProperty("type", f.type());
                fo.addProperty("risk", f.risk());
                fo.addProperty("confidence", f.confidence());
                fo.addProperty("title", f.title());
                fo.addProperty("evidence", f.evidence());
                fo.addProperty("location", f.location());
                findingsArr.add(fo);
            }
            result.add("findings", findingsArr);
            if (!lastResult.findings().isEmpty()) {
                result.addProperty("next_step", buildNextStep(lastResult.findings()));
            }
            return result.toString();
        } catch (Exception e) {
            return "{\"success\": false, \"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...[truncated]";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private String buildNextStep(List<VulnFinding> findings) {
        for (var f : findings) {
            String type = f.type() != null ? f.type().toLowerCase() : "";
            if (type.contains("sql") || type.contains("注入")) {
                return "建议: 发现 SQL 注入线索，调用 generate_payloads 生成针对性 payload，然后调用 send_request 验证";
            }
            if (type.contains("越权") || type.contains("idor") || type.contains("auth") || type.contains("未授权")) {
                return "建议: 发现越权/鉴权线索，调用 test_auth_bypass 做多 session 交叉验证";
            }
            if (type.contains("ssrf") || type.contains("url")) {
                return "建议: 发现 SSRF 线索，调用 generate_oob_probe 获取探针域名，然后调用 send_request 测试";
            }
            if (type.contains("xss") || type.contains("反射")) {
                return "建议: 发现 XSS 线索，调用 generate_payloads 生成 XSS payload，然后调用 send_request 验证反射";
            }
        }
        return "建议: 调用 generate_payloads 生成针对性测试 payload，然后调用 send_request 逐个验证";
    }
}
