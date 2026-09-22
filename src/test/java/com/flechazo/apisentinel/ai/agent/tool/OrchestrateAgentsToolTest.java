package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * OrchestrateAgentsTool 单元测试
 *
 * 验证 orchestrate_agents 工具的参数校验、工作流类型校验，以及 execute-only
 * 工作流（不触发 LLM）下的响应构建。多 Agent 协调的内部逻辑由
 * {@link com.flechazo.apisentinel.ai.agent.MultiAgentCoordinatorTest} 覆盖。
 *
 * @since 1.1.0
 */
class OrchestrateAgentsToolTest {

    private OrchestrateAgentsTool newTool() {
        // logger 非空（MultiAgentCoordinator.execute 直接调用 logger.info，无 null 守卫）
        return new OrchestrateAgentsTool(
                new ToolContext(null, null, null, null, null, null, new LeveledLogger(null)));
    }

    private JsonObject exec(String argsJson) {
        return JsonParser.parseString(newTool().execute(argsJson)).getAsJsonObject();
    }

    // ==================== 元数据 ====================

    @Test
    void name_isOrchestrateAgents() {
        assertEquals("orchestrate_agents", newTool().name());
    }

    @Test
    void description_mentionsRolesAndWorkflows() {
        String desc = newTool().description();
        assertTrue(desc.contains("Planner"));
        assertTrue(desc.contains("Executor"));
        assertTrue(desc.contains("full"));
    }

    @Test
    void isReadOnly_usesAgentToolDefault() {
        // 未覆写 isReadOnly()，沿用 AgentTool 默认值 false
        assertFalse(newTool().isReadOnly());
    }

    @Test
    void inputSchema_requiresTargetApi() {
        JsonObject schema = newTool().inputSchema();
        assertEquals("object", schema.get("type").getAsString());
        assertTrue(schema.has("required"));
        assertEquals("target_api", schema.getAsJsonArray("required").get(0).getAsString());
        JsonObject props = schema.getAsJsonObject("properties");
        assertTrue(props.has("target_api"));
        assertTrue(props.has("workflow"));
        assertTrue(props.has("focus_areas"));
    }

    // ==================== 参数校验 ====================

    @Test
    void execute_missingTargetApi_returnsError() {
        JsonObject out = exec("{\"workflow\":\"full\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertEquals("target_api is required", out.get("error").getAsString());
    }

    @Test
    void execute_blankTargetApi_returnsError() {
        JsonObject out = exec("{\"target_api\":\"   \"}");
        assertFalse(out.get("success").getAsBoolean());
        assertEquals("target_api is required", out.get("error").getAsString());
    }

    @Test
    void execute_invalidWorkflow_returnsError() {
        JsonObject out = exec("{\"target_api\":\"GET /api/x\",\"workflow\":\"bogus\"}");
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("workflow"));
    }

    @Test
    void execute_invalidJson_returnsError() {
        JsonObject out = JsonParser.parseString(newTool().execute("{not json")).getAsJsonObject();
        assertFalse(out.get("success").getAsBoolean());
        assertTrue(out.get("error").getAsString().toLowerCase().contains("json"));
    }

    @Test
    void execute_validWorkflowTypes_accepted() {
        // 'execute' 工作流不调用 LLM；full/plan/verify 会触发 mock-null provider 导致
        // planner 失败（被 MultiAgentCoordinator 的 try/catch 兜住），但都不是"非法 workflow"错误。
        for (String wf : new String[]{"full", "plan", "execute", "verify"}) {
            JsonObject out = exec("{\"target_api\":\"GET /api/x\",\"workflow\":\"" + wf + "\"}");
            String invalidMsg = "Invalid workflow type. Use: full, plan, execute, or verify";
            // 不应出现非法 workflow 错误（可能无 error 字段，或有其他错误）
            assertTrue(!out.has("error") || !out.get("error").getAsString().equals(invalidMsg),
                    "workflow=" + wf + " 应被接受");
        }
    }

    // ==================== execute 工作流（无 LLM） ====================

    @Test
    void execute_executeWorkflow_buildsResponseWithMetadata() {
        JsonObject out = exec("{\"target_api\":\"POST /api/orders\",\"workflow\":\"execute\"}");

        assertTrue(out.get("success").getAsBoolean());
        assertEquals("POST /api/orders", out.get("target_api").getAsString());
        assertEquals("execute", out.get("workflow").getAsString());
        assertTrue(out.has("phases_completed"));
        assertTrue(out.has("phases_failed"));
        assertTrue(out.has("next_step"));
        // agent_outputs 数组应存在
        assertTrue(out.has("agent_outputs"));
    }

    @Test
    void execute_executeWorkflow_focusAreasPropagated() {
        JsonObject out = exec("""
                {"target_api":"GET /api/users/{id}","workflow":"execute",
                 "focus_areas":"authentication,authorization"}
                """);
        assertEquals("authentication,authorization", out.get("focus_areas").getAsString());
    }

    @Test
    void execute_defaultWorkflowIsFull() {
        // 不传 workflow 时默认 "full" → 会触发 planner（null provider → 失败），
        // 但响应应携带 workflow="full"
        JsonObject out = exec("{\"target_api\":\"GET /api/x\"}");
        assertEquals("full", out.get("workflow").getAsString());
    }
}
