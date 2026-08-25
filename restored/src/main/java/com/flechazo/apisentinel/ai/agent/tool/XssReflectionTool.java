package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.XssReflectionVerifier;
import com.flechazo.apisentinel.detection.XssReflectionVerifier.XssReflectionResult;
import com.flechazo.apisentinel.detection.BlindParamMutator;
import com.google.gson.JsonObject;

public class XssReflectionTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sendTool;

    public XssReflectionTool(ToolContext ctx, SendRequestTool sendTool) {
        this.ctx = ctx;
        this.sendTool = sendTool;
    }

    @Override
    public String name() { return "verify_xss_reflection"; }

    @Override
    public String description() {
        return "Verify reflected XSS on one parameter: injects a unique alphanumeric canary, "
             + "checks if it appears in the response, then probes with angle brackets to confirm "
             + "the server does NOT HTML-encode them. Returns reflection context (IN_HTML, "
             + "IN_ATTRIBUTE, IN_SCRIPT, IN_JSON, ENCODED). Two-phase: canary (no WAF trigger) "
             + "then tag probe (confirms exploitability). Max 2 requests.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("param_name", prop("string", "待验证参数名（必填）"));
        props.add("param_value", prop("string", "参数当前值（必填，用于替换）"));
        props.add("param_location", prop("string",
                "参数位置: query|body_json|body_form|header|cookie（可选，自动探测）"));
        schema.add("properties", props);
        schema.add("required", com.google.gson.JsonParser.parseString("[\"param_name\",\"param_value\"]"));
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject out = new JsonObject();
        try {
            JsonObject args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            String paramName = getStr(args, "param_name");
            String paramValue = getStr(args, "param_value");
            String paramLocation = args.has("param_location")
                    ? args.get("param_location").getAsString()
                    : BlindParamMutator.locateParam(ctx.entry(), paramName);

            if (paramName == null || paramName.isEmpty()) {
                out.addProperty("error", "param_name 必填");
                return out.toString();
            }

            XssReflectionVerifier verifier = new XssReflectionVerifier(
                    ctx.montoyaApi(), ctx.logger(), ctx.pipelineConfig().wafDetectionEnabled());

            XssReflectionResult result = verifier.verify(ctx.entry(), paramName, paramLocation, paramValue);

            out.addProperty("reflected", result.reflected());
            out.addProperty("unfiltered", result.unfiltered());
            out.addProperty("context", result.context().name());
            out.addProperty("waf_blocked", result.wafBlocked());
            out.addProperty("detail", result.detail());
            if (result.statusCode() > 0) {
                out.addProperty("status_code", result.statusCode());
                out.addProperty("response_time_ms", result.elapsedMs());
            }
            if (result.unfiltered()) {
                out.addProperty("note", "XSS 反射已程序化确认: 尖括号未被编码，可构造有效 XSS payload");
            } else if (result.reflected()) {
                out.addProperty("note", "参数被反射但尖括号被编码/过滤。"
                        + "尝试: 事件属性注入(onmouseover)、JS上下文逃逸、或 WAF bypass 后重试");
            }
        } catch (Exception e) {
            out.addProperty("error", e.getMessage());
        }
        return out.toString();
    }

    private static JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private static String getStr(JsonObject o, String key) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsString() : null;
    }
}
