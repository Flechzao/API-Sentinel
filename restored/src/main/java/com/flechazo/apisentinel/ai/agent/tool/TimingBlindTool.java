package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.detection.BlindParamMutator;
import com.flechazo.apisentinel.detection.BlindVerificationResult;
import com.flechazo.apisentinel.detection.TimingBlindVerifier;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool: timing-based blind SQLi verification (SLEEP payloads). Use as
 * the last resort when boolean blind also failed. Adds real latency (5s per
 * positive probe); auto mode tries each DB's sleep function in turn.
 */
public class TimingBlindTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sendTool;

    public TimingBlindTool(ToolContext ctx, SendRequestTool sendTool) {
        this.ctx = ctx;
        this.sendTool = sendTool;
    }

    @Override
    public String name() { return "verify_timing_blind"; }

    @Override
    public String description() {
        return "Verify timing-based blind SQL injection on one parameter: injects a "
             + "DB-specific SLEEP payload and confirms when the response is delayed >=4.5s. "
             + "Use after verify_boolean_blind also failed. db_type=auto tries every DB in "
             + "turn (up to 6 requests total). Skipped automatically when the baseline is "
             + "slower than 2s.";
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
        props.add("db_type", prop("string", "可选: mysql/postgresql/mssql/oracle/sqlite/auto（默认 auto）"));
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
            String dbType = getStr(args, "db_type");

            BlindVerificationResult r = new TimingBlindVerifier(ctx.montoyaApi(), ctx.logger())
                    .verify(ctx.entry(), paramName, location, paramValue, dbType.isEmpty() ? "auto" : dbType);

            if (!r.sentRequest().isEmpty() && sendTool != null) {
                TestCase tc = new TestCase("时序盲注-" + paramName, "盲注验证", paramName,
                        "SLEEP 探针 (" + r.dbType() + ")", "", "", null, "",
                        "程序化时序盲注验证",
                        r.confirmed() ? "响应延迟确认注入" : "无延迟", "HIGH");
                sendTool.getPayloadResults().add(new PayloadResult(
                        tc, r.sentRequest(), r.receivedResponse(), r.statusCode(),
                        r.elapsedMs(), r.confirmed(), System.currentTimeMillis(), -1));
            }

            out.addProperty("confirmed", r.confirmed());
            out.addProperty("method", r.method());
            out.addProperty("db_type", r.dbType());
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
