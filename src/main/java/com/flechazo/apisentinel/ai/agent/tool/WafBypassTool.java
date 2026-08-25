package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.detection.WafBypassEncoder;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool: retry a WAF-blocked payload through an ordered bypass chain
 * (case mixing / comment obfuscation / encoding / IP variants / tag
 * rewrites depending on vuln class). Max 4 requests; returns the bypassing
 * payload so the agent can continue verifying with it.
 */
public class WafBypassTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sendTool;

    public WafBypassTool(ToolContext ctx, SendRequestTool sendTool) {
        this.ctx = ctx;
        this.sendTool = sendTool;
    }

    @Override
    public String name() { return "waf_bypass_retry"; }

    @Override
    public String description() {
        return "Retry a WAF-blocked payload with ordered bypass strategies (case mixing, "
             + "comment obfuscation, encoding, separator/IP/tag substitution — chosen by "
             + "vuln_type). Max 4 requests. Returns the bypassing payload when one passes "
             + "the WAF, so you can continue verification with it.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("vuln_type", prop("string",
                "漏洞类型: sql_injection|command_injection|ssrf|xss|path_traversal（必填）"));
        props.add("original_payload", prop("string", "被拦截的原始 payload（必填）"));
        props.add("param_name", prop("string", "payload 所在参数名（payload 未原样出现在请求中时必填）"));
        props.add("param_location", prop("string",
                "参数位置: query|body_json|body_form|header|cookie（可选，自动探测）"));
        schema.add("properties", props);
        return schema;
    }

    private static JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject out = new JsonObject();
        try {
            JsonObject args = JsonParser.parseString(argumentsJson).getAsJsonObject();
            String vulnType = getStr(args, "vuln_type");
            String payload = getStr(args, "original_payload");
            if (vulnType.isEmpty() || payload.isEmpty()) {
                out.addProperty("error", "vuln_type 与 original_payload 必填");
                return out.toString();
            }
            String paramName = getStr(args, "param_name");
            String paramLocation = getStr(args, "param_location");
            if (paramLocation.isEmpty() && !paramName.isEmpty()) {
                paramLocation = com.flechazo.apisentinel.detection.BlindParamMutator
                        .locateParam(ctx.entry(), paramName);
            }

            boolean wafEnabled = ctx.pipelineConfig() == null || ctx.pipelineConfig().wafDetectionEnabled();
            WafBypassEncoder.BypassResult r = new WafBypassEncoder(
                    ctx.montoyaApi(), ctx.logger(), wafEnabled)
                    .attemptBypass(ctx.entry(), vulnType, payload, paramName, paramLocation);

            if (!r.sentRequest().isEmpty() && sendTool != null) {
                TestCase tc = new TestCase("WAF绕过-" + r.strategy(), "WAF绕过", paramName,
                        r.bypassPayload(), "", "", null, "",
                        "WAF 绕过策略链重试", r.detail(), "MEDIUM");
                sendTool.getPayloadResults().add(new PayloadResult(
                        tc, r.sentRequest(), r.receivedResponse(), r.statusCode(),
                        0, r.bypassed(), System.currentTimeMillis(), -1));
            }

            out.addProperty("bypassed", r.bypassed());
            out.addProperty("strategy", r.strategy());
            out.addProperty("bypass_payload", r.bypassPayload());
            out.addProperty("detail", r.detail());
            return out.toString();
        } catch (Exception e) {
            out.addProperty("error", e.getMessage());
            return out.toString();
        }
    }

    private static String getStr(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : "";
    }
}
