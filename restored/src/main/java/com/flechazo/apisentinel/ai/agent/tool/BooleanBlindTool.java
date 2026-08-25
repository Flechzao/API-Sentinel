package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.detection.BlindParamMutator;
import com.flechazo.apisentinel.detection.BlindVerificationResult;
import com.flechazo.apisentinel.detection.BooleanBlindVerifier;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool: boolean-based blind SQLi verification for a single parameter.
 * Use when error-based injection failed but the parameter is still suspected.
 * Returns a short conclusion (~150 chars) — full responses are recorded as
 * PayloadResults for the verdict cross-validation chain.
 */
public class BooleanBlindTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sendTool;

    public BooleanBlindTool(ToolContext ctx, SendRequestTool sendTool) {
        this.ctx = ctx;
        this.sendTool = sendTool;
    }

    @Override
    public String name() { return "verify_boolean_blind"; }

    @Override
    public String description() {
        return "Verify boolean-based blind SQL injection on one parameter: sends a true "
             + "condition (value AND 1=1) and a false condition (value AND 1=2), then "
             + "compares status codes and response lengths. Use when error-based injection "
             + "failed but the parameter is still suspected injectable. Free, 2 requests.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("param_name", prop("string", "参数名（必填）"));
        props.add("param_value", prop("string", "参数当前值（必填，来自捕获的请求）"));
        props.add("param_location", prop("string",
                "参数位置: query|body_json|body_form|header|cookie（缺省自动探测）"));
        props.add("db_type", prop("string", "可选: mysql/postgresql/mssql/oracle/sqlite/auto"));
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
            String paramName = getStr(args, "param_name");
            String paramValue = getStr(args, "param_value");
            if (paramName.isEmpty()) {
                out.addProperty("error", "param_name 必填");
                return out.toString();
            }
            String location = getStr(args, "param_location");
            if (location.isEmpty()) location = BlindParamMutator.locateParam(ctx.entry(), paramName);

            boolean wafEnabled = ctx.pipelineConfig() == null || ctx.pipelineConfig().wafDetectionEnabled();
            BlindVerificationResult r = new BooleanBlindVerifier(
                    ctx.montoyaApi(), ctx.logger(), wafEnabled)
                    .verify(ctx.entry(), paramName, location, paramValue);

            if (!r.sentRequest().isEmpty() && sendTool != null) {
                // payload = r.detail(): since the verifier embeds the full
                // true/false payload texts in the detail, this keeps the
                // PayloadResult matchable by VerdictValidator no matter which
                // half (true or false) the LLM cites in payloadUsed. The old
                // hard-coded "true: v AND 1=1 / false: AND 1=2" missed the
                // param value on the false side, so a natural citation like
                // "1 AND 1=2" matched nothing and the confirmed blind-SQLi
                // finding got demoted to suspected.
                TestCase tc = new TestCase("布尔盲注-" + paramName, "盲注验证", paramName,
                        r.detail(),
                        "", "", null, "", "程序化布尔盲注验证",
                        r.confirmed() ? "true/false 响应差异确认注入" : "无差异", "HIGH");
                sendTool.getPayloadResults().add(new PayloadResult(
                        tc, r.sentRequest(), r.receivedResponse(), r.statusCode(),
                        r.elapsedMs(), r.confirmed(), System.currentTimeMillis(), -1));
            }

            out.addProperty("confirmed", r.confirmed());
            out.addProperty("method", r.method());
            out.addProperty("waf_blocked", r.wafBlocked());
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
