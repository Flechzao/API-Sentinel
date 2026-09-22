package com.flechazo.apisentinel.ai.provider;

import com.flechazo.apisentinel.ai.budget.TokenBudgetManager;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for the budget-gate sink (P0-6 fix).
 *
 * <p>Before {@link BudgetedLlmProvider} existed, the shared
 * {@link TokenBudgetManager} was only consulted inside
 * {@link com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue#submit},
 * so the three higher-value entry paths (single-endpoint Agent,
 * single-endpoint Pipeline, and the 40-turn chat-mode ReAct loop)
 * bypassed the gate entirely. Worse, {@code setDailyBudget} /
 * {@code setPerRequestMax} had zero callers, so the hardcoded 500K/50K
 * limit could not even be tuned by the user.
 *
 * <p>These tests pin the contract of the decorator and the factory
 * integration, so the gate cannot silently regress.
 */
class BudgetedLlmProviderTest {

    /** Fake provider whose complete() is fully scripted — no network, no
     *  thinking, no caching. Usage fields are set explicitly so the test
     *  can prove the decorator reads the right numbers. */
    static class FakeProvider implements LlmProvider {
        final java.util.concurrent.atomic.AtomicInteger callCount = new java.util.concurrent.atomic.AtomicInteger();
        LlmResponse scripted;

        FakeProvider(LlmResponse scripted) { this.scripted = scripted; }

        @Override public String getId() { return "fake"; }
        @Override public String getDisplayName() { return "Fake"; }
        @Override public boolean supportsToolCalling() { return false; }
        @Override public boolean supportsExtendedThinking() { return false; }
        @Override public void configure(String endpoint, String apiKey, String model) {}
        @Override public int estimateTokens(String text) { return text.length() / 4; }
        @Override public boolean isAvailable() { return true; }
        @Override public CompletableFuture<Boolean> testConnection() {
            return CompletableFuture.completedFuture(true);
        }
        @Override public CompletableFuture<LlmResponse> complete(LlmRequest request) {
            callCount.incrementAndGet();
            return CompletableFuture.completedFuture(scripted);
        }
    }

    private static LlmResponse fakeResponse(int inputTokens, int completionTokens,
                                            int cacheCreation, int cacheRead) {
        return new LlmResponse("ok", inputTokens, completionTokens, 10L, "fake",
                LlmResponse.FinishReason.COMPLETE, null,
                List.of(), null, null, cacheCreation, cacheRead);
    }

    @Test
    void rejectsWhenDailyBudgetExceededWithoutCallingDelegate() {
        TokenBudgetManager bm = new TokenBudgetManager(100, 50);
        bm.setBudgetMode(com.flechazo.apisentinel.ai.budget.BudgetMode.ENFORCE);
        bm.recordUsage("fake", 200); // already over budget
        FakeProvider fake = new FakeProvider(fakeResponse(10, 5, 0, 0));

        BudgetedLlmProvider budgeted = new BudgetedLlmProvider(fake, bm);
        LlmResponse resp = budgeted.complete(new LlmRequest("sys", "user")).join();

        assertThat(resp.finishReason()).isEqualTo(LlmResponse.FinishReason.RATE_LIMITED);
        assertThat(resp.errorMessage()).contains("budget");
        assertThat(fake.callCount.get())
                .as("delegate must NOT be called when the gate rejects — otherwise "
                        + "we'd still pay the API cost for a result we won't use")
                .isZero();
        assertThat(bm.getTodayUsed())
                .as("no usage recorded when the call was rejected pre-flight")
                .isEqualTo(200);
    }

    @Test
    void acceptsWhenUnderBudgetAndRecordsBillableUsage() {
        TokenBudgetManager bm = new TokenBudgetManager(100_000, 50_000);
        // Scripted: 1000 input + 500 output + 5200 cache-creation + 0 cache-read.
        // Billable input (per LlmResponse.billableInputTokens) = 1000 + 5200 + 0 = 6200.
        // Usage recorded = billable input + completion = 6200 + 500 = 6700.
        FakeProvider fake = new FakeProvider(fakeResponse(1000, 500, 5200, 0));

        BudgetedLlmProvider budgeted = new BudgetedLlmProvider(fake, bm);
        LlmResponse resp = budgeted.complete(new LlmRequest("sys", "user")).join();

        assertThat(resp.finishReason()).isEqualTo(LlmResponse.FinishReason.COMPLETE);
        assertThat(fake.callCount.get()).isEqualTo(1);
        assertThat(bm.getTodayUsed())
                .as("usage must reflect the INVOICE, not the legacy promptTokens "
                        + "field — cache-creation tokens are paid at the write rate "
                        + "and must count against the daily budget")
                .isEqualTo(6700);
    }

    @Test
    void recordsCacheReadTokensAgainstBudget() {
        TokenBudgetManager bm = new TokenBudgetManager(100_000, 50_000);
        // 500 input + 200 output + 0 cache-creation + 8000 cache-read.
        // Cache reads are billed at ~10% of input rate on Anthropic; the
        // budget tracks raw token counts (the cost math lives elsewhere),
        // but they MUST count against the daily cap — otherwise a cache-
        // heavy workload could burn through the paid budget without the
        // gate ever tripping.
        FakeProvider fake = new FakeProvider(fakeResponse(500, 200, 0, 8000));

        BudgetedLlmProvider budgeted = new BudgetedLlmProvider(fake, bm);
        budgeted.complete(new LlmRequest("sys", "user")).join();

        assertThat(bm.getTodayUsed()).isEqualTo(500 + 8000 + 200);
    }

    @Test
    void unwrapReturnsOriginalDelegate() {
        TokenBudgetManager bm = new TokenBudgetManager();
        FakeProvider fake = new FakeProvider(fakeResponse(1, 1, 0, 0));
        BudgetedLlmProvider budgeted = new BudgetedLlmProvider(fake, bm);
        assertThat(budgeted.unwrap()).isSameAs(fake);
    }

    @Test
    void wrappingAlreadyWrappedProviderDoesNotDoubleWrap() {
        TokenBudgetManager bm = new TokenBudgetManager();
        FakeProvider fake = new FakeProvider(fakeResponse(1, 1, 0, 0));
        BudgetedLlmProvider first = new BudgetedLlmProvider(fake, bm);
        BudgetedLlmProvider second = new BudgetedLlmProvider(first, bm);
        assertThat(second.unwrap()).isSameAs(fake);
    }

    @Test
    void delegatesIdentityAndCapabilityCalls() {
        TokenBudgetManager bm = new TokenBudgetManager();
        FakeProvider fake = new FakeProvider(fakeResponse(1, 1, 0, 0));
        BudgetedLlmProvider budgeted = new BudgetedLlmProvider(fake, bm);
        assertThat(budgeted.getId()).isEqualTo("fake");
        assertThat(budgeted.isAvailable()).isTrue();
        assertThat(budgeted.supportsToolCalling()).isFalse();
        assertThat(budgeted.estimateTokens("1234")).isEqualTo(1);
    }

    @Test
    void factoryWrapsWhenBudgetManagerSet() {
        LlmProviderFactory factory = new LlmProviderFactory();
        TokenBudgetManager bm = new TokenBudgetManager();
        factory.setBudgetManager(bm);

        // Every registered provider, when fetched, must come back wrapped.
        for (LlmProvider raw : factory.getAll().values()) {
            LlmProvider fetched = factory.get(raw.getId());
            assertThat(fetched).isInstanceOf(BudgetedLlmProvider.class);
            assertThat(((BudgetedLlmProvider) fetched).unwrap()).isSameAs(raw);
        }
    }

    @Test
    void factoryReturnsRawWhenNoBudgetManager() {
        LlmProviderFactory factory = new LlmProviderFactory();
        // No setBudgetManager call.
        for (LlmProvider raw : factory.getAll().values()) {
            LlmProvider fetched = factory.get(raw.getId());
            assertThat(fetched).isNotInstanceOf(BudgetedLlmProvider.class);
            assertThat(fetched).isSameAs(raw);
        }
    }

    @Test
    void factoryGetFirstAvailableAlsoWraps() {
        LlmProviderFactory factory = new LlmProviderFactory();
        TokenBudgetManager bm = new TokenBudgetManager();
        factory.setBudgetManager(bm);
        LlmProvider picked = factory.getFirstAvailable();
        // If any provider is available, it must be wrapped.
        if (picked != null) {
            assertThat(picked).isInstanceOf(BudgetedLlmProvider.class);
        }
    }

    @Test
    void nullDelegatesRejected() {
        TokenBudgetManager bm = new TokenBudgetManager();
        org.junit.jupiter.api.Assertions.assertThrows(
                NullPointerException.class,
                () -> new BudgetedLlmProvider(null, bm));
        org.junit.jupiter.api.Assertions.assertThrows(
                NullPointerException.class,
                () -> new BudgetedLlmProvider(new FakeProvider(fakeResponse(1,1,0,0)), null));
    }
}
