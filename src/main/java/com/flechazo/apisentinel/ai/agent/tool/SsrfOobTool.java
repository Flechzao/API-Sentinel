package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.detection.OobService;
import com.google.gson.JsonObject;

public class SsrfOobTool implements AgentTool {

    private final ToolContext ctx;

    public SsrfOobTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "generate_oob_probe"; }

    @Override
    public String description() {
        return "Generate a unique OOB probe hostname for blind-SSRF/XXE/SSTI/RCE detection. "
             + "Embed the returned hostname in URL/redirect/entity parameters and send via "
             + "send_request. After sending, call check_oob_results to verify if the target "
             + "contacted the probe (confirms blind vuln). Optionally specify 'parameter' and "
             + "'vuln_type' for accurate tracking. Free, no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        JsonObject paramProp = new JsonObject();
        paramProp.addProperty("type", "string");
        paramProp.addProperty("description", "Parameter name this probe targets (e.g. 'url', 'redirect', 'callback')");
        props.add("parameter", paramProp);
        JsonObject vulnProp = new JsonObject();
        vulnProp.addProperty("type", "string");
        vulnProp.addProperty("description", "Vulnerability type: SSRF, XXE, SSTI, RCE. Default: SSRF");
        props.add("vuln_type", vulnProp);
        schema.add("properties", props);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        OobService oob = ctx.oobService();
        if (oob == null || !oob.isEnabled()) {
            JsonObject out = new JsonObject();
            out.addProperty("enabled", false);
            out.addProperty("hint", "OOB 检测未启用。请在设置中开启并配置 Collaborator 或内部 dnslog。");
            return out.toString();
        }

        String parameter = null;
        String vulnType = "SSRF";
        try {
            var args = com.google.gson.JsonParser.parseString(argumentsJson).getAsJsonObject();
            if (args.has("parameter")) parameter = args.get("parameter").getAsString();
            if (args.has("vuln_type")) vulnType = args.get("vuln_type").getAsString();
        } catch (Exception ignored) {}

        String entryId = ctx.entry() != null ? ctx.entry().getId() : null;
        String entryPath = ctx.entry() != null ? ctx.entry().getApiPath() : null;

        String probe = oob.generatePayload(entryId, entryPath, parameter, vulnType);
        JsonObject out = new JsonObject();
        if (probe == null) {
            out.addProperty("error", "无法生成探针 payload，请检查 OOB 平台配置");
            return out.toString();
        }
        out.addProperty("probe", probe);
        out.addProperty("probe_url", "http://" + probe);
        out.addProperty("vuln_type", vulnType);
        if (parameter != null) out.addProperty("parameter", parameter);
        out.addProperty("usage", "Inject this hostname into the suspect parameter, send the request "
                + "with send_request, then call check_oob_results after a few seconds to confirm.");
        return out.toString();
    }
}
