package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.detection.ActiveProbeExecutor;
import com.google.gson.JsonObject;

import java.util.List;

/**
 * Runs the programmatic active probes (CORS origin variants, JWT alg:none
 * forgery replay, CRLF canary, NoSQL differential/timing) on the current
 * entry and merges the results into {@link SendRequestTool}'s collected
 * PayloadResults — so the AgentLoop's verification count, VerdictValidator
 * cross-check and markConfirmedPayloads all cover probe results for free.
 *
 * Probe logic lives in {@link ActiveProbeExecutor} (shared with Pipeline
 * Stage 5.5); this tool only adapts it to the Agent tool protocol.
 */
public class ActiveProbeTool implements AgentTool {

    private final ToolContext ctx;
    private final SendRequestTool sendTool;

    public ActiveProbeTool(ToolContext ctx, SendRequestTool sendTool) {
        this.ctx = ctx;
        this.sendTool = sendTool;
    }

    @Override
    public String name() { return "active_probe"; }

    @Override
    public String description() {
        return "Run programmatic active probes on the current endpoint: CORS origin-variant "
             + "reflection, JWT alg:none forgery replay, CRLF canary injection, NoSQL "
             + "differential/timing tests. Trigger-condition driven (only fires probes that "
             + "apply), free, no AI cost. Confirmed issues are recorded as verified payloads.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        schema.add("properties", new JsonObject());
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject out = new JsonObject();
        if (ctx.pipelineConfig() != null && !ctx.pipelineConfig().activeProbeEnabled()) {
            out.addProperty("enabled", false);
            out.addProperty("hint", "主动探针未启用（工具栏 检测组 → 主动探针 复选框）。");
            return out.toString();
        }
        if (ctx.montoyaApi() == null) {
            out.addProperty("error", "Montoya API unavailable");
            return out.toString();
        }

        boolean wafEnabled = ctx.pipelineConfig() == null || ctx.pipelineConfig().wafDetectionEnabled();
        List<PayloadResult> results =
                new ActiveProbeExecutor(ctx.montoyaApi(), ctx.logger(), wafEnabled)
                        .execute(ctx.entry());
        // Merge into send_request's result list so the ReAct loop's existing
        // verification accounting and verdict cross-validation see them.
        if (sendTool != null && !results.isEmpty()) {
            sendTool.getPayloadResults().addAll(results);
        }

        long confirmed = results.stream().filter(PayloadResult::anomalyDetected).count();
        out.addProperty("enabled", true);
        out.addProperty("probe_responses", results.size());
        out.addProperty("programmatically_confirmed", confirmed);
        for (PayloadResult pr : results) {
            if (pr.anomalyDetected() && pr.testCase() != null) {
                out.addProperty("confirmed_detail",
                        pr.testCase().name() + " (status=" + pr.statusCode() + ")");
                break;
            }
        }
        out.addProperty("note", confirmed > 0
                ? "存在程序化确认的发现，可直接作为 confirmed 证据（引用对应 payload）。"
                : "探针未见确认发现；探针结果已并入验证记录。");
        return out.toString();
    }
}
