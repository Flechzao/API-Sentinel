package com.flechazo.apisentinel.ai.provider;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class LlmProviderFactory {

    private final Map<String, LlmProvider> providers = new LinkedHashMap<>();
    private final ExecutorService llmExecutor;

    public LlmProviderFactory() {
        this.llmExecutor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "api-sentinel-llm-io");
            t.setDaemon(true);
            return t;
        });
        register(new OllamaProvider());
        register(new ClaudeProvider());
        register(new OpenAiProvider());
    }

    public void register(LlmProvider provider) {
        providers.put(provider.getId(), provider);
        if (provider instanceof OpenAiProvider p) p.setExecutor(llmExecutor);
        else if (provider instanceof ClaudeProvider p) p.setExecutor(llmExecutor);
        else if (provider instanceof OllamaProvider p) p.setExecutor(llmExecutor);
    }

    public LlmProvider get(String providerId) {
        return providers.get(providerId);
    }

    public Map<String, LlmProvider> getAll() {
        return Map.copyOf(providers);
    }

    public LlmProvider getFirstAvailable() {
        for (LlmProvider p : providers.values()) {
            if (p.isAvailable()) return p;
        }
        return null;
    }

    public ExecutorService getLlmExecutor() {
        return llmExecutor;
    }

    public void shutdown() {
        llmExecutor.shutdownNow();
        try {
            llmExecutor.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
