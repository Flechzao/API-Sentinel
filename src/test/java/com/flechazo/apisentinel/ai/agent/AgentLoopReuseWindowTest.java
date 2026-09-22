package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.pipeline.*;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.AnalysisRecord;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Reuse-window soft fold: AgentLoop.buildPriorAnalysisContext injects the
 * prior verdict into the initial user message so the agent confirms/corrects
 * rather than re-derives from scratch. Mirrors AnalysisPipeline's mechanism
 * but never short-circuits the loop (advisory input only).
 *
 * <p>See docs/plan/reuse-window-agent-migration.md §3.1 / §7.
 */
class AgentLoopReuseWindowTest {

    private static LlmProvider provider() {
        return new LlmProvider() {
            @Override public String getId() { return "fake"; }
            @Override public String getDisplayName() { return "Fake"; }
            @Override public CompletableFuture<Boolean> testConnection() {
                return CompletableFuture.completedFuture(true);
            }
            @Override public CompletableFuture<LlmResponse> complete(LlmRequest request) {
                return CompletableFuture.failedFuture(new IllegalStateException("unexpected"));
            }
            @Override public int estimateTokens(String text) { return text == null ? 0 : text.length() / 4; }
            @Override public boolean isAvailable() { return true; }
            @Override public void configure(String endpoint, String apiKey, String model) {}
        };
    }

    private static AnalysisConfig config() {
        return new AnalysisConfig(true, 10, true, false,
                "", "A", "", "B", 200_000, true,
                false, false, false, false, 0, false, false);
    }

    private static AgentLoop newLoop() {
        return new AgentLoop(provider(), null, null, config(), List.of(),
                new LeveledLogger(null), null);
    }

    private static FinalVerdict verdict(String risk,
                                         List<ConfirmedVuln> confirmed,
                                         List<SuspectedVuln> suspected,
                                         String summary) {
        return new FinalVerdict(risk, confirmed, suspected, summary,
                "", 0, List.of());
    }

    private static PipelineResult pipelineResult(FinalVerdict verdict) {
        return new PipelineResult(null, null, List.of(), List.of(),
                verdict, Map.of());
    }

    /** Build an ApiEntry with a prior AnalysisRecord whose timestamp is
     *  {@code ageMs} milliseconds in the past. */
    private static ApiEntry entryWithPrior(long ageMs, FinalVerdict verdict) {
        ApiEntry entry = new ApiEntry("GET", "/api/users/search");
        AnalysisRecord record = new AnalysisRecord("agent", null)
                .withPipelineResult(pipelineResult(verdict));
        // Replace the auto-generated timestamp with one `ageMs` ago.
        AnalysisRecord timestamped = new AnalysisRecord(
                record.id(),
                System.currentTimeMillis() - ageMs,
                record.mode(), record.result(), record.testCases(),
                record.pipelineResult(), record.timeline());
        entry.addAnalysisRecord(timestamped);
        return entry;
    }

    // ────────────────────────────── positive ──────────────────────────────

    @Test
    void withinWindow_injectsPriorVerdictSection() {
        AgentLoop loop = newLoop();
        loop.setReuseWindowMinutes(30);

        FinalVerdict v = verdict("HIGH",
                List.of(new ConfirmedVuln("SQL_INJECTION", "name 参数拼接",
                        "evidence", "' OR 1=1--", "resp", "cmd",
                        "", "", -1)),
                List.of(new SuspectedVuln("IDOR", "缺少归属校验",
                        "reason", "cmd", "medium", "")),
                "发现 SQL 注入和疑似 IDOR");
        ApiEntry entry = entryWithPrior(/* 10 min ago */ 10 * 60_000L, v);

        String ctx = loop.buildPriorAnalysisContext(entry);

        assertThat(ctx)
                .contains("上次分析结论")
                .contains("30 分钟内")
                .contains("请确认/修正而非重新推导")
                .contains("HIGH")
                .contains("[SQL_INJECTION] name 参数拼接")
                .contains("[IDOR] 缺少归属校验")
                .contains("发现 SQL 注入和疑似 IDOR");
    }

    @Test
    void safeVerdict_injectsCorrectly() {
        AgentLoop loop = newLoop();
        loop.setReuseWindowMinutes(30);

        FinalVerdict v = verdict("SAFE", List.of(), List.of(), "无异常");
        ApiEntry entry = entryWithPrior(5 * 60_000L, v);

        String ctx = loop.buildPriorAnalysisContext(entry);

        assertThat(ctx).contains("SAFE").contains("无异常");
        // No vulns section when lists are empty.
        assertThat(ctx).doesNotContain("已确认漏洞").doesNotContain("疑似漏洞");
    }

    // ────────────────────────────── negative ──────────────────────────────

    @Test
    void disabled_returnsEmpty() {
        AgentLoop loop = newLoop();
        loop.setReuseWindowMinutes(0);  // disabled

        FinalVerdict v = verdict("HIGH", List.of(), List.of(), "");
        ApiEntry entry = entryWithPrior(5 * 60_000L, v);

        assertThat(loop.buildPriorAnalysisContext(entry)).isEmpty();
    }

    @Test
    void outsideWindow_returnsEmpty() {
        AgentLoop loop = newLoop();
        loop.setReuseWindowMinutes(30);

        FinalVerdict v = verdict("HIGH", List.of(), List.of(), "");
        // 60 minutes ago — outside the 30-minute window.
        ApiEntry entry = entryWithPrior(60 * 60_000L, v);

        assertThat(loop.buildPriorAnalysisContext(entry)).isEmpty();
    }

    @Test
    void noPriorRecord_returnsEmpty() {
        AgentLoop loop = newLoop();
        loop.setReuseWindowMinutes(30);

        ApiEntry entry = new ApiEntry("GET", "/api/fresh");

        assertThat(loop.buildPriorAnalysisContext(entry)).isEmpty();
    }

    @Test
    void noPipelineResult_returnsEmpty() {
        AgentLoop loop = newLoop();
        loop.setReuseWindowMinutes(30);

        ApiEntry entry = new ApiEntry("GET", "/api/no-pipeline");
        // Record with no pipeline result (legacy constructor).
        entry.addAnalysisRecord(new AnalysisRecord("agent", null));

        assertThat(loop.buildPriorAnalysisContext(entry)).isEmpty();
    }

    @Test
    void negativeAgeMs_returnsEmpty() {
        AgentLoop loop = newLoop();
        loop.setReuseWindowMinutes(30);

        // Timestamp in the future (clock skew guard).
        FinalVerdict v = verdict("HIGH", List.of(), List.of(), "");
        ApiEntry entry = entryWithPrior(/* future */ -60_000L, v);

        assertThat(loop.buildPriorAnalysisContext(entry)).isEmpty();
    }

    // ────────────────────────────── integration ───────────────────────────

    @Test
    void setterClampsNegativeToZero() {
        AgentLoop loop = newLoop();
        loop.setReuseWindowMinutes(-5);

        FinalVerdict v = verdict("HIGH", List.of(), List.of(), "");
        ApiEntry entry = entryWithPrior(5 * 60_000L, v);

        // Clamped to 0 → disabled → empty.
        assertThat(loop.buildPriorAnalysisContext(entry)).isEmpty();
    }
}
