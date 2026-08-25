package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.XxeProbeVerifier;
import com.flechazo.apisentinel.detection.XxeProbeVerifier.XxeResult;
import com.google.gson.JsonObject;

public class XxeProbeTool implements AgentTool {

    private final ToolContext ctx;

    public XxeProbeTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "verify_xxe"; }

    @Override
    public String description() {
        return "Verify XML External Entity (XXE) injection: replaces the request body with "
             + "crafted XML containing entity definitions that read local files (/etc/passwd, "
             + "win.ini). Two modes: 'inband' checks response for file content; 'oob' sends "
             + "an entity referencing a Collaborator URL (call check_oob_results later). "
             + "Requires the target to accept XML input. Max 4 in-band + 1 OOB request.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("mode", prop("string", "inband|oob|auto（可选，默认 auto 先试内联再试 OOB）"));
        props.add("target_os", prop("string", "目标操作系统: linux|windows|auto（可选，默认 auto）"));
        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject out = new JsonObject();
        try {
            JsonObject args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            String mode = getStr(args, "mode");
            String targetOs = getStr(args, "target_os");

            XxeProbeVerifier verifier = new XxeProbeVerifier(
                    ctx.montoyaApi(), ctx.logger(), ctx.oobService(),
                    ctx.pipelineConfig().wafDetectionEnabled());

            XxeResult result = verifier.verify(ctx.entry(), mode, targetOs);

            out.addProperty("confirmed", result.confirmed());
            if (result.mode() != null) out.addProperty("mode_used", result.mode());
            if (result.technique() != null) out.addProperty("technique", result.technique());
            if (result.evidenceSnippet() != null) out.addProperty("evidence_snippet", result.evidenceSnippet());
            if (result.oobProbe() != null) out.addProperty("oob_probe", result.oobProbe());
            out.addProperty("waf_blocked", result.wafBlocked());
            out.addProperty("detail", result.detail());
            if (result.statusCode() > 0) {
                out.addProperty("status_code", result.statusCode());
                out.addProperty("response_time_ms", result.elapsedMs());
            }
            if (result.oobProbe() != null && !result.confirmed()) {
                out.addProperty("note", "OOB 探针已发送，请在后续步骤中调用 check_oob_results 确认是否有 DNS/HTTP 回连");
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
