package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.detection.BusinessLogicVerifier;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Agent tool: programmatic business-logic flaw tests (price tamper, step
 * skip, negative value, coupon reuse, concurrent race, batch enumeration).
 * These perform REAL business operations — invoke only when the target is
 * authorized for such testing.
 */
public class BusinessLogicTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sendTool;

    public BusinessLogicTool(ToolContext ctx, SendRequestTool sendTool) {
        this.ctx = ctx;
        this.sendTool = sendTool;
    }

    @Override
    public String name() { return "verify_business_logic"; }

    @Override
    public String description() {
        return "Verify business-logic flaws programmatically. test_type: tamper_price "
             + "(try 0.01/-100/1e-10), step_skip (jump to a later step), negative_value "
             + "(-1/-100), repeat_coupon (same coupon twice), concurrent_race (N parallel "
             + "identical requests), batch_enumeration (adjacent IDs → IDOR). Performs REAL "
             + "business operations — authorized targets only.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        props.add("test_type", prop("string",
                "tamper_price|step_skip|negative_value|repeat_coupon|concurrent_race|batch_enumeration（必填）"));
        props.add("target_param", prop("string", "目标参数名（tamper_price/negative_value/batch_enumeration 用）"));
        props.add("target_value", prop("string", "替换值（可选，缺省用内置探测值）"));
        props.add("target_step", prop("string", "step_skip 的目标步骤（可选，缺省 final）"));
        props.add("count", prop("integer", "concurrent_race 并发数（可选，默认 5，上限 10）"));
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
            BusinessLogicVerifier.TestType type =
                    BusinessLogicVerifier.TestType.fromInput(getStr(args, "test_type"));
            if (type == null) {
                out.addProperty("error", "test_type 无效，可选: tamper_price|step_skip|"
                        + "negative_value|repeat_coupon|concurrent_race|batch_enumeration");
                return out.toString();
            }
            BusinessLogicVerifier.Params params = new BusinessLogicVerifier.Params();
            params.targetParam = getStr(args, "target_param");
            String tv = getStr(args, "target_value");
            params.targetValue = tv.isEmpty() ? null : tv;
            String ts = getStr(args, "target_step");
            params.targetStep = ts.isEmpty() ? null : ts;
            if (args.has("count") && args.get("count").isJsonPrimitive()) {
                try { params.count = args.get("count").getAsInt(); } catch (Exception ignored) {}
            }

            BusinessLogicVerifier.LogicFlawResult r =
                    new BusinessLogicVerifier(ctx.montoyaApi(), ctx.logger())
                            .verify(type, ctx.entry(), params);

            if (!r.sentRequest().isEmpty() && sendTool != null) {
                TestCase tc = new TestCase("业务逻辑-" + type.name(), "业务逻辑",
                        params.targetParam, r.detail(), "", "", null, "",
                        "程序化业务逻辑验证", r.confirmed() ? "程序化确认" : "未确认", "HIGH");
                sendTool.getPayloadResults().add(new PayloadResult(
                        tc, r.sentRequest(), r.receivedResponse(), r.statusCode(),
                        0, r.confirmed(), System.currentTimeMillis(), -1));
            }

            out.addProperty("confirmed", r.confirmed());
            out.addProperty("test_type", type.name().toLowerCase());
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
