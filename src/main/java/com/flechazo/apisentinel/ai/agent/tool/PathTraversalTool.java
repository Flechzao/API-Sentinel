package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.PathTraversalVerifier;
import com.flechazo.apisentinel.detection.PathTraversalVerifier.PathTraversalResult;
import com.flechazo.apisentinel.detection.BlindParamMutator;
import com.google.gson.JsonObject;

public class PathTraversalTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sendTool;

    public PathTraversalTool(ToolContext ctx, SendRequestTool sendTool) {
        this.ctx = ctx;
        this.sendTool = sendTool;
    }

    @Override
    public String name() { return "verify_path_traversal"; }

    @Override
    public String description() {
        return "Verify path traversal (LFI) on one parameter: injects ../../etc/passwd and "
             + "encoded variants (double-encoding, UTF-8 overlong, filter bypass), checks if "
             + "the response contains file content signatures (root:x:0:0: or [fonts]). "
             + "Includes baseline comparison to avoid false positives. Max 8 requests.";
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
        props.add("target_os", prop("string", "目标操作系统: linux|windows|auto（可选，默认 auto）"));
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
            String targetOs = getStr(args, "target_os");

            if (paramName == null || paramName.isEmpty()) {
                out.addProperty("error", "param_name 必填");
                return out.toString();
            }

            PathTraversalVerifier verifier = new PathTraversalVerifier(
                    ctx.montoyaApi(), ctx.logger(), ctx.pipelineConfig().wafDetectionEnabled());

            PathTraversalResult result = verifier.verify(ctx.entry(), paramName, paramLocation, paramValue, targetOs);

            out.addProperty("confirmed", result.confirmed());
            if (result.payload() != null) out.addProperty("payload_used", result.payload());
            if (result.technique() != null) out.addProperty("technique", result.technique());
            if (result.evidenceSnippet() != null) out.addProperty("evidence_snippet", result.evidenceSnippet());
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
