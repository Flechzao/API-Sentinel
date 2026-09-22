package com.flechazo.apisentinel.integration;

import com.flechazo.apisentinel.ai.agent.tool.OrchestrateAgentsTool;
import com.flechazo.apisentinel.ai.agent.tool.ToolContext;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 多 Agent 工作流集成测试
 *
 * 用 mock LLM Provider（每轮返回固定文本、无 tool call，使 ExplorationSubAgent 首轮即收敛）
 * 跑完整 {@code full} 工作流，端到端验证 OrchestrateAgentsTool → MultiAgentCoordinator →
 * ExplorationSubAgent 链路：4 阶段顺序（Planner → Explorer → Executor → Verifier）、
 * phases_completed 统计、success 标志。
 *
 * @since 1.1.0
 */
class MultiAgentWorkflowIntegrationTest {

    private ToolContext ctxWith(LlmProvider provider) {
        return new ToolContext(null, provider, null, null, null, null, new LeveledLogger(null));
    }

    private JsonObject runFull(LlmProvider provider, String focusAreas) {
        OrchestrateAgentsTool tool = new OrchestrateAgentsTool(ctxWith(provider));
        String args = "{\"target_api\":\"GET /api/users/{id}\",\"workflow\":\"full\""
                + (focusAreas != null ? ",\"focus_areas\":\"" + focusAreas + "\"" : "") + "}";
        return JsonParser.parseString(tool.execute(args)).getAsJsonObject();
    }

    @Test
    void fullWorkflow_runsAllFourPhasesInOrder() {
        JsonObject out = runFull(new AlwaysSucceedsProvider(), null);

        assertTrue(out.get("success").getAsBoolean(), "4 阶段全部成功 → success=true");
        assertEquals("GET /api/users/{id}", out.get("target_api").getAsString());
        assertEquals("full", out.get("workflow").getAsString());
        assertEquals(4, out.getAsJsonArray("agent_outputs").size(), "应产出 4 个阶段输出");
        assertEquals(4, out.get("phases_completed").getAsInt());
        assertEquals(0, out.get("phases_failed").getAsInt());

        // 顺序断言：PLANNER → EXPLORER → EXECUTOR → VERIFIER
        var outputs = out.getAsJsonArray("agent_outputs");
        assertEquals("PLANNER", outputs.get(0).getAsJsonObject().get("role").getAsString());
        assertEquals("EXPLORER", outputs.get(1).getAsJsonObject().get("role").getAsString());
        assertEquals("EXECUTOR", outputs.get(2).getAsJsonObject().get("role").getAsString());
        assertEquals("VERIFIER", outputs.get(3).getAsJsonObject().get("role").getAsString());
    }

    @Test
    void fullWorkflow_eachPhaseProducesNonEmptySummary() {
        JsonObject out = runFull(new AlwaysSucceedsProvider(), "authentication,authorization");
        var outputs = out.getAsJsonArray("agent_outputs");
        // Planner/Explorer/Verifier 走 LLM（有 summary）；Executor 是占位（summary 为固定文案）
        for (int i = 0; i < outputs.size(); i++) {
            JsonObject phase = outputs.get(i).getAsJsonObject();
            assertTrue(phase.get("success").getAsBoolean(), "phase " + i + " 应成功");
            assertNotNull(phase.get("summary"), "phase " + i + " 应有 summary");
            assertFalse(phase.get("summary").getAsString().isBlank());
        }
        // focus_areas 透传
        assertEquals("authentication,authorization", out.get("focus_areas").getAsString());
    }

    @Test
    void executeOnlyWorkflow_skipsPlannerExplorerVerifier() {
        // execute 工作流只跑 Executor 占位，不调用 LLM
        OrchestrateAgentsTool tool = new OrchestrateAgentsTool(
                new ToolContext(null, null, null, null, null, null, new LeveledLogger(null)));
        JsonObject out = JsonParser.parseString(tool.execute(
                "{\"target_api\":\"POST /api/orders\",\"workflow\":\"execute\"}")).getAsJsonObject();

        assertTrue(out.get("success").getAsBoolean());
        assertEquals(1, out.getAsJsonArray("agent_outputs").size());
        assertEquals("EXECUTOR", out.getAsJsonArray("agent_outputs").get(0)
                .getAsJsonObject().get("role").getAsString());
        assertEquals(1, out.get("phases_completed").getAsInt());
    }

    /**
     * 每轮返回带文本的 COMPLETE 响应（无 tool call），
     * ExplorationSubAgent 首轮即判定为最终结论 → success=true。
     */
    static final class AlwaysSucceedsProvider implements LlmProvider {
        @Override
        public CompletableFuture<LlmResponse> complete(LlmRequest request) {
            return CompletableFuture.completedFuture(new LlmResponse(
                    "分析完成：未发现新增风险，建议关注鉴权与注入。",
                    10, 20, 0, "mock",
                    LlmResponse.FinishReason.COMPLETE, null));
        }

        @Override
        public String getId() { return "mock-always"; }

        @Override
        public String getDisplayName() { return "Always-Succeeds Mock"; }

        @Override
        public CompletableFuture<Boolean> testConnection() {
            return CompletableFuture.completedFuture(true);
        }

        @Override
        public int estimateTokens(String text) { return 0; }

        @Override
        public boolean isAvailable() { return true; }

        @Override
        public void configure(String endpoint, String apiKey, String model) { }
    }
}
