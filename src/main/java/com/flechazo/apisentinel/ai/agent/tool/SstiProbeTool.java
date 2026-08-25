package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.SstiProbeVerifier;
import com.flechazo.apisentinel.detection.SstiProbeVerifier.SstiResult;
import com.flechazo.apisentinel.detection.BlindParamMutator;
import com.google.gson.JsonObject;

public class SstiProbeTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sendTool;

    public SstiProbeTool(ToolContext ctx, SendRequestTool sendTool) {
        this.ctx = ctx;
        this.sendTool = sendTool;
    }

    @Override
    public String name() { return "verify_ssti"; }

    @Override
    public String description() {
        return "Verify Server-Side Template Injection on one parameter: injects template "
             + "expressions ({{7*7}}, ${7*7}, <%= 7*7 %>, etc.) and checks if the response "
             + "contains the computed result (49). Includes a control request to guard against "
             + "false positives. Supports: jinja2, freemarker, erb, smarty, velocity, pebble. "
             + "Max ~8 requests (auto) or ~2 requests (specific engine).";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("param_name", prop("string", "待验证参数名（必填）"));
        props.add("param_value", prop("string", "参数当前值（必填）"));
        props.add("param_location", prop("string",
                "参数位置: query|body_json|body_form|header|cookie（可选，自动探测）"));
        props.add("template_engine", prop("string",
                "指定模板引擎: jinja2|freemarker|erb|smarty|velocity|pebble|auto（可选，默认 auto 全试）"));
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
            String engine = getStr(args, "template_engine");

            if (paramName == null || paramName.isEmpty()) {
                out.addProperty("error", "param_name 必填");
                return out.toString();
            }

            SstiProbeVerifier verifier = new SstiProbeVerifier(
                    ctx.montoyaApi(), ctx.logger(), ctx.pipelineConfig().wafDetectionEnabled());

            SstiResult result = verifier.verify(ctx.entry(), paramName, paramLocation, paramValue, engine);

            out.addProperty("confirmed", result.confirmed());
            if (result.engine() != null) out.addProperty("template_engine", result.engine());
            if (result.expression() != null) out.addProperty("expression_used", result.expression());
            out.addProperty("waf_blocked", result.wafBlocked());
            out.addProperty("detail", result.detail());
            if (result.statusCode() > 0) {
                out.addProperty("status_code", result.statusCode());
                out.addProperty("response_time_ms", result.elapsedMs());
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
