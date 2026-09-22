package com.flechazo.apisentinel.ai.provider;

import com.flechazo.apisentinel.ai.budget.TokenBudgetManager;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class LlmProviderFactory {

    private final Map<String, LlmProvider> providers = new LinkedHashMap<>();
    private final ExecutorService llmExecutor;
    /** When non-null, {@link #get} and {@link #getFirstAvailable} return
     *  {@link BudgetedLlmProvider} wrappers so every LLM call — including
     *  the three direct (non-queue) entry paths in AgentFacade,
     *  PipelineFacade, and ChatController — pays the budget gate. */
    private volatile TokenBudgetManager budgetManager;

    public LlmProviderFactory() {
        this.llmExecutor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "api-sentinel-llm-io");
            t.setDaemon(true);
            return t;
        });
        register(new OllamaProvider());
        register(new ClaudeProvider());
        register(new OpenAiProvider());
        register(new DeepSeekProvider());
    }

    public void register(LlmProvider provider) {
        providers.put(provider.getId(), provider);
        if (provider instanceof OpenAiProvider p) p.setExecutor(llmExecutor);
        else if (provider instanceof ClaudeProvider p) p.setExecutor(llmExecutor);
        else if (provider instanceof OllamaProvider p) p.setExecutor(llmExecutor);
        else if (provider instanceof DeepSeekProvider p) p.setExecutor(llmExecutor);
    }

    /** Installs the shared budget manager. Once set, all providers handed
     *  out by {@link #get} / {@link #getFirstAvailable} enforce the daily
     *  budget and record real usage. Calling with {@code null} disables
     *  wrapping (used in tests that want to drive the raw provider). */
    public void setBudgetManager(TokenBudgetManager budgetManager) {
        this.budgetManager = budgetManager;
    }

    public TokenBudgetManager getBudgetManager() {
        return budgetManager;
    }

    public LlmProvider get(String providerId) {
        LlmProvider raw = providers.get(providerId);
        return wrapIfBudgeted(raw);
    }

    public Map<String, LlmProvider> getAll() {
        // Callers that iterate getAll() (e.g. the settings panel showing
        // every provider) see the unwrapped providers — they need the
        // concrete class for {@code instanceof} dispatch (executor wiring,
        // capability queries). Budget wrapping is applied at the narrower
        // get() / getFirstAvailable() boundary where a single provider is
        // chosen for a real LLM call.
        return Map.copyOf(providers);
    }

    public LlmProvider getFirstAvailable() {
        for (LlmProvider p : providers.values()) {
            if (p.isAvailable()) return wrapIfBudgeted(p);
        }
        return null;
    }

    private LlmProvider wrapIfBudgeted(LlmProvider raw) {
        if (raw == null) return null;
        TokenBudgetManager bm = budgetManager;
        return bm != null ? new BudgetedLlmProvider(raw, bm) : raw;
    }

    public ExecutorService getLlmExecutor() {
        return llmExecutor;
    }

    public void shutdown() {
        llmExecutor.shutdownNow();
        // Close each provider's HttpClient (releases SelectorManager threads
        // on Java 21+, best-effort no-op on Java 17).
        for (LlmProvider p : providers.values()) {
            try { p.close(); } catch (Exception ignored) {}
        }
        // Release all provider references — each holds a java.net.http.HttpClient
        // with internal thread pools (SelectorManager, connection pool). Clearing
        // the map lets GC reclaim them even though Java 17 HttpClient has no
        // explicit close() method.
        providers.clear();
        budgetManager = null;
        try {
            llmExecutor.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
