package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.ai.agent.MultiAgentCoordinator;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * orchestrate_agents — 多 Agent 协作编排工具
 *
 * 参考 PentAGI 的多 Agent 协作模式，协调不同角色的 Agent 完成复杂的安全测试工作流：
 *
 * **工作流阶段**：
 * 1. **Planner** — 分析攻击面，生成测试计划（只读）
 * 2. **Explorer** — 深度探索代码仓库，发现潜在漏洞（只读）
 * 3. **Executor** — 执行实际测试，验证漏洞（可发送请求）
 * 4. **Verifier** — 独立验证发现，减少误报（可发送请求）
 *
 * **工作流类型**：
 * - `full` — 完整 4 阶段流程（默认）
 * - `plan` — 仅规划阶段
 * - `execute` — 仅执行阶段
 * - `verify` — 仅验证阶段
 *
 * 每个阶段的输出作为下一阶段的输入，形成协作链。
 *
 * @since 1.2.0
 */
public class OrchestrateAgentsTool implements AgentTool {

    private final ToolContext ctx;

    public OrchestrateAgentsTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() { return "orchestrate_agents"; }

    @Override
    public String description() {
        return "Orchestrate a multi-agent collaboration workflow for comprehensive security testing. "
             + "Coordinates 4 specialized agent roles: Planner (strategy), Explorer (code analysis), "
             + "Executor (testing), and Verifier (validation). Each agent's output feeds into the next, "
             + "creating a collaborative testing pipeline. Workflow types: 'full' (all 4 phases), "
             + "'plan' (planning only), 'execute' (testing only), 'verify' (validation only). "
             + "Best for complex APIs requiring deep analysis + testing + verification. "
             + "Consumes AI for each phase.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();

        props.add("target_api", prop("string",
                "Target API to test (e.g. 'POST /api/orders', 'GET /api/users/{id}')"));

        props.add("workflow", prop("string",
                "Workflow type: 'full' (default), 'plan', 'execute', or 'verify'"));

        props.add("focus_areas", prop("string",
                "Optional: comma-separated focus areas (e.g. 'authentication,authorization,injection')"));

        schema.add("properties", props);
        JsonArray required = new JsonArray();
        required.add("target_api");
        schema.add("required", required);
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        JsonObject args;
        try {
            args = JsonParser.parseString(argumentsJson).getAsJsonObject();
        } catch (Exception e) {
            return err("Invalid JSON: " + e.getMessage());
        }

        String targetApi = str(args, "target_api");
        String workflow = str(args, "workflow", "full");
        String focusAreas = str(args, "focus_areas");

        if (targetApi == null || targetApi.isBlank()) {
            return err("target_api is required");
        }

        // Validate workflow type
        if (!workflow.equals("full") && !workflow.equals("plan")
                && !workflow.equals("execute") && !workflow.equals("verify")) {
            return err("Invalid workflow type. Use: full, plan, execute, or verify");
        }

        if (ctx.logger() != null) {
            ctx.logger().info("[orchestrate_agents] Starting %s workflow for %s (focus: %s)",
                    workflow, targetApi, focusAreas != null ? focusAreas : "none");
        }

        // Create coordinator and execute workflow
        MultiAgentCoordinator coordinator = new MultiAgentCoordinator(
                ctx.provider(), ctx, ctx.logger()
        );

        MultiAgentCoordinator.CoordinationResult result = coordinator.execute(targetApi, workflow);

        // Build response
        JsonObject out = result.toJson();
        out.addProperty("target_api", targetApi);
        out.addProperty("workflow", workflow);
        if (focusAreas != null) {
            out.addProperty("focus_areas", focusAreas);
        }

        // Add summary
        int successCount = 0;
        int failCount = 0;
        for (MultiAgentCoordinator.AgentOutput output : result.outputs()) {
            if (output.success()) successCount++;
            else failCount++;
        }

        out.addProperty("phases_completed", successCount);
        out.addProperty("phases_failed", failCount);

        if (result.success()) {
            out.addProperty("next_step", "Multi-agent workflow completed successfully. "
                    + "Review each phase's output for findings and recommendations.");
        } else {
            out.addProperty("next_step", "Workflow partially completed. Check failed phases for details.");
        }

        return out.toString();
    }

    private static JsonObject prop(String type, String desc) {
        JsonObject p = new JsonObject();
        p.addProperty("type", type);
        p.addProperty("description", desc);
        return p;
    }

    private static String str(JsonObject obj, String key) {
        return str(obj, key, null);
    }

    private static String str(JsonObject obj, String key, String def) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return def;
    }

    private static String err(String msg) {
        JsonObject o = new JsonObject();
        o.addProperty("success", false);
        o.addProperty("error", msg);
        return o.toString();
    }
}
