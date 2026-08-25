package com.flechazo.apisentinel.ai.provider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * Ollama LLM Provider——连接本地 Ollama 服务，数据不出本机，适配小窗口模型。
 */
public class OllamaProvider implements LlmProvider {

    private static final Gson GSON = new Gson();
    private volatile String endpoint = "http://localhost:11434";
    private volatile String model = "llama3";
    private final HttpClient httpClient;
    private volatile java.util.concurrent.ExecutorService executor;

    public OllamaProvider() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public void setExecutor(java.util.concurrent.ExecutorService executor) {
        this.executor = executor;
    }

    @Override
    public String getId() { return "ollama"; }

    @Override
    public String getDisplayName() { return "Ollama (Local)"; }

    @Override
    public void configure(String endpoint, String apiKey, String model) {
        if (endpoint != null && !endpoint.isBlank()) this.endpoint = endpoint;
        if (model != null && !model.isBlank()) this.model = model;
    }

    @Override
    public CompletableFuture<Boolean> testConnection() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(endpoint + "/api/tags"))
                        .timeout(Duration.ofSeconds(5))
                        .GET()
                        .build();
                HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
                return resp.statusCode() == 200;
            } catch (Exception e) {
                return false;
            }
        });
    }

    /** Model to use for this request: the per-request override (multi-model
     *  tiering) when set, otherwise the provider's configured default. */
    private String effectiveModel(LlmRequest request) {
        String ovr = request != null ? request.modelOverride() : null;
        return (ovr != null && !ovr.isBlank()) ? ovr : model;
    }

    @Override
    public CompletableFuture<LlmResponse> complete(LlmRequest request) {
        var future = executor != null
                ? CompletableFuture.supplyAsync(() -> doComplete(request), executor)
                : CompletableFuture.supplyAsync(() -> doComplete(request));
        return future;
    }

    private static final int MAX_RETRIES = 2;

    private LlmResponse doComplete(LlmRequest request) {
        long start = System.currentTimeMillis();
        Exception lastException = null;

        for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            try {
                if (attempt > 0) {
                    Thread.sleep(3000L * attempt);
                }

                JsonObject body = new JsonObject();
                body.addProperty("model", effectiveModel(request));
                body.addProperty("stream", false);

                if ("json".equals(request.responseFormat())) {
                    body.addProperty("format", "json");
                }

                JsonObject options = new JsonObject();
                options.addProperty("temperature", request.temperature());
                options.addProperty("num_predict", request.maxTokens());
                body.add("options", options);

                JsonArray messages = new JsonArray();
                if (request.isMultiTurn()) {
                    for (ChatMessage msg : request.messages()) {
                        if ("tool".equals(msg.role())) continue;
                        JsonObject m = new JsonObject();
                        m.addProperty("role", msg.role());
                        m.addProperty("content", msg.content() != null ? msg.content() : "");
                        messages.add(m);
                    }
                } else {
                    if (request.systemPrompt() != null && !request.systemPrompt().isEmpty()) {
                        JsonObject sysMsg = new JsonObject();
                        sysMsg.addProperty("role", "system");
                        sysMsg.addProperty("content", request.systemPrompt());
                        messages.add(sysMsg);
                    }
                    JsonObject userMsg = new JsonObject();
                    userMsg.addProperty("role", "user");
                    userMsg.addProperty("content", request.userPrompt() != null ? request.userPrompt() : "");
                    messages.add(userMsg);
                }
                body.add("messages", messages);

                HttpRequest httpReq = HttpRequest.newBuilder()
                        .uri(URI.create(endpoint + "/api/chat"))
                        .timeout(Duration.ofSeconds(180))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)))
                        .build();

                HttpResponse<String> resp = httpClient.send(httpReq, HttpResponse.BodyHandlers.ofString());
                long latency = System.currentTimeMillis() - start;

                if (resp.statusCode() != 200) {
                    return LlmResponse.error("Ollama returned status " + resp.statusCode() + ": " + resp.body());
                }

                JsonObject result = GSON.fromJson(resp.body(), JsonObject.class);
                String content = result.getAsJsonObject("message").get("content").getAsString();

                int promptTokens = 0;
                int completionTokens = 0;
                if (result.has("prompt_eval_count")) {
                    promptTokens = result.get("prompt_eval_count").getAsInt();
                }
                if (result.has("eval_count")) {
                    completionTokens = result.get("eval_count").getAsInt();
                }

                return new LlmResponse(content, promptTokens, completionTokens,
                        latency, model, LlmResponse.FinishReason.COMPLETE, null);
            } catch (Exception e) {
                lastException = e;
                if (isRetryable(e) && attempt < MAX_RETRIES) {
                    continue;
                }
                long latency = System.currentTimeMillis() - start;
                String errMsg = e.getMessage();
                if (errMsg == null || errMsg.isEmpty()) errMsg = e.getClass().getSimpleName();
                if (attempt > 0) errMsg += " (已重试 " + attempt + " 次)";
                return new LlmResponse("", 0, 0, latency, model, LlmResponse.FinishReason.ERROR, errMsg);
            }
        }
        long latency = System.currentTimeMillis() - start;
        return new LlmResponse("", 0, 0, latency, model, LlmResponse.FinishReason.ERROR,
                lastException != null ? lastException.getMessage() : "未知错误");
    }

    private static boolean isRetryable(Exception e) {
        String msg = (e.getMessage() != null ? e.getMessage() : "").toLowerCase();
        Throwable cause = e.getCause();
        String causeMsg = cause != null && cause.getMessage() != null ? cause.getMessage().toLowerCase() : "";
        return msg.contains("eof") || msg.contains("end of file")
                || msg.contains("connection reset") || msg.contains("broken pipe")
                || msg.contains("stream is closed") || msg.contains("premature")
                || causeMsg.contains("eof") || causeMsg.contains("end of file")
                || causeMsg.contains("connection reset") || causeMsg.contains("broken pipe")
                || causeMsg.contains("stream is closed") || causeMsg.contains("premature")
                || e instanceof java.io.EOFException
                || cause instanceof java.io.EOFException;
    }

    @Override
    public int estimateTokens(String text) {
        return text.length() / 4;
    }

    @Override
    public boolean isAvailable() {
        try {
            // Bound the probe so a dead/unreachable Ollama cannot block
            // getFirstAvailable() indefinitely — it sits first in the chain.
            return testConnection().get(3, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception e) {
            return false;
        }
    }
}
