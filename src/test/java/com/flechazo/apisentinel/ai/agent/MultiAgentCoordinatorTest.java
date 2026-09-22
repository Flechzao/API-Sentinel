package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.tool.ToolContext;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MultiAgentCoordinator 单元测试
 *
 * 覆盖：输入校验、CoordinationResult 工厂与 toJson、execute-only 工作流（无需 LLM）、
 * plan 工作流（mock LLM）、planner 失败时降级为 partial。
 *
 * @since 1.1.0
 */
class MultiAgentCoordinatorTest {

    private ToolContext ctx() {
        // cheapModelOverride() 在 appConfig==null 时返回 null，不触发 NPE
        return new ToolContext(null, null, null, null, null, null, new LeveledLogger(null));
    }

    private MultiAgentCoordinator coordinator(LlmProvider provider) {
        return new MultiAgentCoordinator(provider, ctx(), new LeveledLogger(null));
    }

    // ==================== 输入校验 ====================

    @Test
    void execute_nullTarget_returnsError() {
        MultiAgentCoordinator.CoordinationResult r = coordinator(null).execute(null, "full");
        assertFalse(r.success());
        assertEquals("failed", r.status());
        assertEquals("targetApi must not be empty", r.error());
        assertTrue(r.outputs().isEmpty());
    }

    @Test
    void execute_blankTarget_returnsError() {
        MultiAgentCoordinator.CoordinationResult r = coordinator(null).execute("   ", "full");
        assertFalse(r.success());
        assertEquals("targetApi must not be empty", r.error());
    }

    @Test
    void execute_nullWorkflow_defaultsToFull() {
        // execute-only 不调用 LLM，但 null workflow 走 "full" 分支会调用 LLM。
        // 用 mock provider 避免真实调用，断言不抛异常且产生输出。
        MultiAgentCoordinator.CoordinationResult r =
                coordinator(new MockProvider("plan")).execute("GET /api/x", null);
        assertNotNull(r);
        assertTrue(r.outputs().size() >= 1);
    }

    // ==================== execute-only 工作流（无 LLM） ====================

    @Test
    void execute_onlyExecuteWorkflow_runsWithoutLlm() {
        // execute 工作流只跑 Executor 占位阶段，不调用 LLM → provider 可为 null
        MultiAgentCoordinator.CoordinationResult r = coordinator(null).execute("POST /api/orders", "execute");

        assertTrue(r.success());
        assertEquals("completed", r.status());
        assertEquals(1, r.outputs().size());
        MultiAgentCoordinator.AgentOutput exec = r.outputs().get(0);
        assertEquals(AgentRole.EXECUTOR, exec.role());
        assertTrue(exec.success());
    }

    // ==================== plan 工作流（mock LLM） ====================

    @Test
    void execute_planWorkflow_plannerPhaseSucceeds() {
        MultiAgentCoordinator.CoordinationResult r =
                coordinator(new MockProvider("plan")).execute("GET /api/users/{id}", "plan");

        assertTrue(r.success());
        assertEquals(1, r.outputs().size());
        MultiAgentCoordinator.AgentOutput planner = r.outputs().get(0);
        assertEquals(AgentRole.PLANNER, planner.role());
        assertTrue(planner.success());
        assertNotNull(planner.summary());
        assertFalse(planner.summary().isBlank());
    }

    // ==================== planner 失败 → partial ====================

    @Test
    void execute_fullWorkflow_plannerFails_returnsPartial() {
        MultiAgentCoordinator.CoordinationResult r =
                coordinator(new MockProvider(null)).execute("GET /api/x", "full");

        // planner 失败 → 提前返回 partial，只有 1 个输出
        assertFalse(r.success());
        assertEquals("Planner phase failed", r.status());
        assertEquals(1, r.outputs().size());
        assertFalse(r.outputs().get(0).success());
    }

    // ==================== CoordinationResult 工厂 ====================

    @Test
    void coordinationResult_successFactory() {
        List<MultiAgentCoordinator.AgentOutput> outs = List.of(
                new MultiAgentCoordinator.AgentOutput(AgentRole.PLANNER, true, "s", null, 1, List.of()));
        MultiAgentCoordinator.CoordinationResult r = MultiAgentCoordinator.CoordinationResult.success(outs);

        assertTrue(r.success());
        assertEquals("completed", r.status());
        assertNull(r.error());
        assertEquals(1, r.outputs().size());
    }

    @Test
    void coordinationResult_partialFactory() {
        MultiAgentCoordinator.CoordinationResult r =
                MultiAgentCoordinator.CoordinationResult.partial(List.of(), "Executor phase failed");
        assertFalse(r.success());
        assertEquals("Executor phase failed", r.status());
    }

    @Test
    void coordinationResult_errorFactory_emptyOutputs() {
        MultiAgentCoordinator.CoordinationResult r = MultiAgentCoordinator.CoordinationResult.error("boom");
        assertFalse(r.success());
        assertEquals("failed", r.status());
        assertEquals("boom", r.error());
        assertTrue(r.outputs().isEmpty());
    }

    // ==================== toJson ====================

    @Test
    void coordinationResult_toJson_containsAllPhases() {
        List<MultiAgentCoordinator.AgentOutput> outs = List.of(
                new MultiAgentCoordinator.AgentOutput(AgentRole.PLANNER, true, "plan summary", null, 2, List.of("search_source_code")),
                new MultiAgentCoordinator.AgentOutput(AgentRole.VERIFIER, false, null, "verify failed", 1, List.of()));
        JsonObject json = MultiAgentCoordinator.CoordinationResult.success(outs).toJson();

        assertTrue(json.get("success").getAsBoolean());
        assertEquals("completed", json.get("status").getAsString());
        assertEquals(2, json.getAsJsonArray("agent_outputs").size());

        JsonObject first = json.getAsJsonArray("agent_outputs").get(0).getAsJsonObject();
        assertEquals("PLANNER", first.get("role").getAsString());
        assertTrue(first.get("success").getAsBoolean());
        assertEquals("plan summary", first.get("summary").getAsString());
        assertEquals(2, first.get("iterations_used").getAsInt());
        assertEquals(1, first.getAsJsonArray("tools_called").size());

        JsonObject second = json.getAsJsonArray("agent_outputs").get(1).getAsJsonObject();
        assertFalse(second.get("success").getAsBoolean());
        assertEquals("verify failed", second.get("error").getAsString());
    }

    @Test
    void coordinationResult_toJson_errorResultHasErrorField() {
        JsonObject json = MultiAgentCoordinator.CoordinationResult.error("workflow failed").toJson();
        assertFalse(json.get("success").getAsBoolean());
        assertEquals("workflow failed", json.get("error").getAsString());
        assertEquals(0, json.getAsJsonArray("agent_outputs").size());
    }

    // ==================== AgentOutput record ====================

    @Test
    void agentOutput_recordAccessors() {
        MultiAgentCoordinator.AgentOutput o =
                new MultiAgentCoordinator.AgentOutput(AgentRole.EXPLORER, true, "summary",
                        null, 3, List.of("read_file", "grep_repo"));
        assertEquals(AgentRole.EXPLORER, o.role());
        assertTrue(o.success());
        assertEquals("summary", o.summary());
        assertNull(o.error());
        assertEquals(3, o.iterationsUsed());
        assertEquals(2, o.toolsCalled().size());
    }

    // ==================== Mock Provider ====================

    /**
     * 可配置返回内容的 mock：planToken 非空 → 返回带文本的成功响应；
     * planToken 为 null → 返回 ERROR 响应（模拟 planner 失败）。
     */
    static final class MockProvider implements LlmProvider {
        private final String planToken;

        MockProvider(String planToken) {
            this.planToken = planToken;
        }

        @Override
        public CompletableFuture<LlmResponse> complete(LlmRequest request) {
            if (planToken == null) {
                return CompletableFuture.completedFuture(LlmResponse.error("LLM 不可用"));
            }
            return CompletableFuture.completedFuture(new LlmResponse(
                    planToken, 10, 20, 0, "mock",
                    LlmResponse.FinishReason.COMPLETE, null));
        }

        @Override
        public String getId() { return "mock"; }

        @Override
        public String getDisplayName() { return "Mock Provider"; }

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
