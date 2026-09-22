package com.flechazo.apisentinel.ai.provider;

import com.flechazo.apisentinel.ai.budget.TokenBudgetManager;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/**
 * A transparent decorator over an {@link LlmProvider} that enforces the
 * shared {@link TokenBudgetManager} on every {@link #complete(LlmRequest)}
 * call.
 *
 * <p>Introduced to plug the P0-6 budget-gate bypass: before this class
 * existed, {@code TokenBudgetManager.canProceed()} / {@code recordUsage()}
 * were only wired into {@link com.flechazo.apisentinel.ai.queue.AnalysisTaskQueue#submit},
 * so three higher-value entry paths bypassed the gate entirely:
 * <ul>
 *   <li>{@code AgentFacade.executeAgentForEntry} — single-endpoint Agent
 *       deep dive, the most expensive per-call path (~110K tokens)</li>
 *   <li>{@code PipelineFacade.executePipelineForEntry} — single-endpoint
 *       Pipeline analysis</li>
 *   <li>{@code ChatController.runEmbeddedToolCallingChat} — the 40-turn
 *       chat-mode ReAct loop</li>
 * </ul>
 * All three obtain their provider via {@link LlmProviderFactory#get} or
 * {@link LlmProviderFactory#getFirstAvailable}, so wrapping at the factory
 * boundary covers every call site in one move — no surgical edits to
 * three facades, and no regression when a new caller appears in future.
 *
 * <p>Accounting uses {@link LlmResponse#billableInputTokens()} so the
 * budget reflects the invoice (input + cache creation + cache read) rather
 * than the legacy {@code promptTokens} field alone.
 */
public class BudgetedLlmProvider implements LlmProvider {

    private final LlmProvider delegate;
    private final TokenBudgetManager budgetManager;
    /** Optional per-analysis cost tracker (null in headless/test). When set,
     *  each LLM call's token usage is recorded for per-endpoint reporting. */
    private volatile com.flechazo.apisentinel.ai.budget.AnalysisCostTracker costTracker;
    /** Reason passed to the caller when the gate rejects a request —
     *  surfaced as a RATE_LIMITED finish so callers that already handle
     *  rate-limit responses degrade gracefully without a new code path. */
    private static final String BUDGET_EXCEEDED_MESSAGE =
            "Daily token budget exceeded (see AI settings to raise it)";

    public BudgetedLlmProvider(LlmProvider delegate, TokenBudgetManager budgetManager) {
        if (delegate == null) throw new NullPointerException("delegate");
        if (budgetManager == null) throw new NullPointerException("budgetManager");
        if (delegate instanceof BudgetedLlmProvider b) {
            // Defensive: avoid stacking wrappers (which would double-count
            // usage and double-check the gate on every call).
            this.delegate = b.delegate;
        } else {
            this.delegate = delegate;
        }
        this.budgetManager = budgetManager;
    }

    /** Returns the underlying (unwrapped) provider — callers that need
     *  provider-specific APIs (e.g. {@code instanceof ClaudeProvider} for
     *  extended thinking setup) use this rather than defeating the
     *  decorator by casting directly. */
    public LlmProvider unwrap() {
        return delegate;
    }

    /** Set a per-analysis cost tracker for this provider. When set, each
     *  LLM call's token usage is recorded for per-endpoint reporting. */
    public void setCostTracker(com.flechazo.apisentinel.ai.budget.AnalysisCostTracker tracker) {
        this.costTracker = tracker;
    }

    @Override public String getId() { return delegate.getId(); }
    @Override public String getDisplayName() { return delegate.getDisplayName(); }
    @Override public boolean supportsToolCalling() { return delegate.supportsToolCalling(); }
    @Override public boolean supportsExtendedThinking() { return delegate.supportsExtendedThinking(); }
    @Override public void configure(String endpoint, String apiKey, String model) {
        delegate.configure(endpoint, apiKey, model);
    }
    @Override public int estimateTokens(String text) { return delegate.estimateTokens(text); }
    @Override public boolean isAvailable() { return delegate.isAvailable(); }
    @Override public CompletableFuture<Boolean> testConnection() { return delegate.testConnection(); }

    @Override
    public CompletableFuture<LlmResponse> complete(LlmRequest request) {
        // Gate check on the caller's thread, before any network IO. A
        // rejection is returned as a ready-completed future with a
        // RATE_LIMITED finish — callers that already handle rate limits
        // (AgentLoop.completeWithRateLimitRetry, ChatController's catch
        // clauses) degrade cleanly without a new code path.
        if (!budgetManager.canProceed()) {
            return CompletableFuture.completedFuture(new LlmResponse(
                    "", 0, 0, 0L, delegate.getId(),
                    LlmResponse.FinishReason.RATE_LIMITED,
                    BUDGET_EXCEEDED_MESSAGE));
        }
        // Record actual billable tokens AFTER the call resolves. We
        // intentionally do NOT pre-reserve with canProceed(estimated):
        // request-side token estimates are known to under-count CJK text
        // by 1.7-2.5× (documented in P0-7), so reservation would either
        // over-reserve (starving legitimate follow-up calls) or under-
        // reserve (making the reservation meaningless). Post-hoc
        // accounting is the honest choice.
        return delegate.complete(request)
                .thenCompose(resp -> {
                    int billable = resp.billableInputTokens() + resp.completionTokens();
                    budgetManager.recordUsage(delegate.getId(), billable);
                    // Per-analysis cost tracking (monitor-only, never blocks)
                    if (costTracker != null) {
                        costTracker.recordCall("LLM call", resp.billableInputTokens(), resp.completionTokens());
                    }
                    return java.util.concurrent.CompletableFuture.completedFuture(resp);
                });
    }
}
