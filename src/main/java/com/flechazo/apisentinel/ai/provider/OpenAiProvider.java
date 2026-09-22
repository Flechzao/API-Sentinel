package com.flechazo.apisentinel.ai.provider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * OpenAI LLM Provider——支持工具调用和 function calling。
 */
public class OpenAiProvider implements LlmProvider {

    private static final Gson GSON = new Gson();
    private volatile String endpoint = "https://api.openai.com/v1/chat/completions";
    private volatile String apiKey = "";
    private volatile String model = "gpt-4o";
    private final HttpClient httpClient;
    private volatile java.util.concurrent.ExecutorService executor;

    public OpenAiProvider() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    public void setExecutor(java.util.concurrent.ExecutorService executor) {
        this.executor = executor;
    }

    @Override
    public String getId() { return "openai"; }

    @Override
    public String getDisplayName() { return "OpenAI (GPT)"; }

    @Override
    public boolean supportsToolCalling() { return true; }

    @Override
    public void configure(String endpoint, String apiKey, String model) {
        if (endpoint != null && !endpoint.isBlank()) this.endpoint = endpoint;
        if (apiKey != null && !apiKey.isBlank()) this.apiKey = apiKey;
        if (model != null && !model.isBlank()) this.model = model;
    }

    @Override
    public CompletableFuture<Boolean> testConnection() {
        LlmRequest testReq = new LlmRequest("You are a test.", "Reply 'ok'.", 10);
        return complete(testReq).thenApply(LlmResponse::isSuccess);
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

                JsonObject body = buildRequestBody(request);

                HttpRequest httpReq = HttpRequest.newBuilder()
                        .uri(URI.create(endpoint))
                        .timeout(Duration.ofSeconds(180))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer " + apiKey)
                        .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)))
                        .build();

                HttpResponse<String> resp = httpClient.send(httpReq, HttpResponse.BodyHandlers.ofString());
                long latency = System.currentTimeMillis() - start;

                if (resp.statusCode() == 429 || resp.statusCode() >= 500) {
                    // Transient: rate-limited or server error. Retry with backoff
                    // (honoring Retry-After) instead of failing immediately.
                    if (attempt < MAX_RETRIES) {
                        Thread.sleep(computeBackoffMs(resp, attempt));
                        continue;
                    }
                    if (resp.statusCode() == 429) {
                        return new LlmResponse("", 0, 0, latency, model,
                                LlmResponse.FinishReason.RATE_LIMITED,
                                "Rate limited (已重试 " + MAX_RETRIES + " 次)");
                    }
                    return LlmResponse.error("OpenAI returned " + resp.statusCode() + ": " + truncateBody(resp.body()));
                }
                if (resp.statusCode() != 200) {
                    return LlmResponse.error("OpenAI returned " + resp.statusCode() + ": " + truncateBody(resp.body()));
                }

                return parseResponse(resp.body(), latency);
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

    /** Model to use for this request: the per-request override (multi-model
     *  tiering) when set, otherwise the provider's configured default. */
    private String effectiveModel(LlmRequest request) {
        String ovr = request != null ? request.modelOverride() : null;
        return (ovr != null && !ovr.isBlank()) ? ovr : model;
    }

    private JsonObject buildRequestBody(LlmRequest request) {
        JsonObject body = new JsonObject();
        body.addProperty("model", effectiveModel(request));
        body.addProperty("max_tokens", request.maxTokens());
        body.addProperty("temperature", request.temperature());

        if (request.isMultiTurn()) {
            buildMultiTurnBody(body, request);
        } else {
            buildSingleTurnBody(body, request);
        }

        if (request.hasTools()) {
            JsonArray toolsArray = new JsonArray();
            for (ToolDefinition td : request.tools()) {
                JsonObject tool = new JsonObject();
                tool.addProperty("type", "function");
                JsonObject func = new JsonObject();
                func.addProperty("name", td.name());
                func.addProperty("description", td.description());
                func.add("parameters", td.inputSchema());
                tool.add("function", func);
                toolsArray.add(tool);
            }
            body.add("tools", toolsArray);
        }

        return body;
    }

    private void buildSingleTurnBody(JsonObject body, LlmRequest request) {
        if ("json".equals(request.responseFormat())) {
            JsonObject fmt = new JsonObject();
            fmt.addProperty("type", "json_object");
            body.add("response_format", fmt);
        }

        JsonArray messages = new JsonArray();
        if (request.systemPrompt() != null && !request.systemPrompt().isEmpty()) {
            JsonObject sysMsg = new JsonObject();
            sysMsg.addProperty("role", "system");
            sysMsg.addProperty("content", request.systemPrompt());
            messages.add(sysMsg);
        }
        JsonObject userMsg = new JsonObject();
        userMsg.addProperty("role", "user");
        userMsg.addProperty("content", request.userPrompt());
        messages.add(userMsg);
        body.add("messages", messages);
    }

    private void buildMultiTurnBody(JsonObject body, LlmRequest request) {
        // Apply the same response_format constraint as single-turn so multi-turn
        // (e.g. tool-calling) flows that expect JSON don't silently drop it.
        if ("json".equals(request.responseFormat())) {
            JsonObject fmt = new JsonObject();
            fmt.addProperty("type", "json_object");
            body.add("response_format", fmt);
        }

        JsonArray messages = new JsonArray();

        for (ChatMessage msg : request.messages()) {
            if ("tool".equals(msg.role())) {
                JsonObject toolMsg = new JsonObject();
                toolMsg.addProperty("role", "tool");
                toolMsg.addProperty("tool_call_id", msg.toolCallId());
                toolMsg.addProperty("content", msg.content());
                messages.add(toolMsg);
                continue;
            }

            if ("assistant".equals(msg.role()) && msg.hasToolCalls()) {
                JsonObject assistantMsg = new JsonObject();
                assistantMsg.addProperty("role", "assistant");
                if (msg.content() != null && !msg.content().isEmpty()) {
                    assistantMsg.addProperty("content", msg.content());
                }
                JsonArray toolCallsArr = new JsonArray();
                for (ToolCall tc : msg.toolCalls()) {
                    JsonObject tcObj = new JsonObject();
                    tcObj.addProperty("id", tc.id());
                    tcObj.addProperty("type", "function");
                    JsonObject funcObj = new JsonObject();
                    funcObj.addProperty("name", tc.toolName());
                    funcObj.addProperty("arguments", tc.arguments());
                    tcObj.add("function", funcObj);
                    toolCallsArr.add(tcObj);
                }
                assistantMsg.add("tool_calls", toolCallsArr);
                messages.add(assistantMsg);
                continue;
            }

            // Vision support: if the message has an image, use multimodal content format
            if (msg.hasImage()) {
                JsonObject m = new JsonObject();
                m.addProperty("role", msg.role());
                JsonArray contentArr = new JsonArray();

                // Text part
                if (msg.content() != null && !msg.content().isEmpty()) {
                    JsonObject textPart = new JsonObject();
                    textPart.addProperty("type", "text");
                    textPart.addProperty("text", msg.content());
                    contentArr.add(textPart);
                }

                // Image part
                JsonObject imagePart = new JsonObject();
                imagePart.addProperty("type", "image_url");
                JsonObject imageUrl = new JsonObject();
                String mimeType = msg.imageMimeType() != null ? msg.imageMimeType() : "image/png";
                imageUrl.addProperty("url", "data:" + mimeType + ";base64," + msg.imageBase64());
                imagePart.add("image_url", imageUrl);
                contentArr.add(imagePart);

                m.add("content", contentArr);
                messages.add(m);
                continue;
            }

            JsonObject m = new JsonObject();
            m.addProperty("role", msg.role());
            m.addProperty("content", msg.content() != null ? msg.content() : "");
            messages.add(m);
        }

        body.add("messages", messages);
    }

    private LlmResponse parseResponse(String responseBody, long latency) {
        JsonObject result = GSON.fromJson(responseBody, JsonObject.class);

        if (!result.has("choices") || result.getAsJsonArray("choices").isEmpty()) {
            return LlmResponse.error("API 返回无效响应: 缺少 choices 字段");
        }

        JsonObject choice = result.getAsJsonArray("choices").get(0).getAsJsonObject();
        JsonObject message = choice.getAsJsonObject("message");

        String finishReason = "stop";
        if (choice.has("finish_reason") && !choice.get("finish_reason").isJsonNull()) {
            finishReason = choice.get("finish_reason").getAsString();
        }

        int promptTokens = 0;
        int completionTokens = 0;
        int cacheRead = 0;
        if (result.has("usage") && !result.get("usage").isJsonNull()) {
            JsonObject usage = result.getAsJsonObject("usage");
            if (usage.has("prompt_tokens")) promptTokens = usage.get("prompt_tokens").getAsInt();
            if (usage.has("completion_tokens")) completionTokens = usage.get("completion_tokens").getAsInt();
            // OpenAI's automatic prompt caching reports cached tokens as a
            // SUBSET of prompt_tokens (Anthropic, by contrast, reports them
            // as SEPARATE fields). To keep LlmResponse.billableInputTokens()
            // provider-agnostic (a simple sum of the three components),
            // split prompt_tokens into the non-cached portion here and let
            // cacheReadInputTokens carry the cached portion. The sum
            // remains equal to the raw prompt_tokens, so the invoice total
            // is unchanged; only the decomposition differs.
            if (usage.has("prompt_tokens_details")
                    && usage.get("prompt_tokens_details").isJsonObject()) {
                JsonObject details = usage.getAsJsonObject("prompt_tokens_details");
                if (details.has("cached_tokens")
                        && details.get("cached_tokens").isJsonPrimitive()) {
                    cacheRead = details.get("cached_tokens").getAsInt();
                    promptTokens = Math.max(0, promptTokens - cacheRead);
                }
            }
        }

        String content = "";
        if (message.has("content") && !message.get("content").isJsonNull()) {
            content = message.get("content").getAsString();
        }

        List<ToolCall> toolCalls = new ArrayList<>();
        if (message.has("tool_calls")) {
            JsonArray tcArray = message.getAsJsonArray("tool_calls");
            for (JsonElement el : tcArray) {
                JsonObject tc = el.getAsJsonObject();
                String id = tc.get("id").getAsString();
                JsonObject func = tc.getAsJsonObject("function");
                String name = func.get("name").getAsString();
                String args = func.get("arguments").getAsString();
                toolCalls.add(new ToolCall(id, name, args));
            }
        }

        LlmResponse.FinishReason reason;
        if ("tool_calls".equals(finishReason)) {
            reason = LlmResponse.FinishReason.TOOL_USE;
        } else if ("length".equals(finishReason)) {
            reason = LlmResponse.FinishReason.MAX_TOKENS;
        } else {
            reason = LlmResponse.FinishReason.COMPLETE;
        }

        return new LlmResponse(content, promptTokens, completionTokens,
                latency, model, reason, null, toolCalls.isEmpty() ? null : toolCalls,
                null, null, 0, cacheRead);
    }

    private static long computeBackoffMs(HttpResponse<String> resp, int attempt) {
        return HttpRetryHelper.computeBackoffMs(resp, attempt);
    }

    private static String truncateBody(String body) {
        return HttpRetryHelper.truncateBody(body);
    }

    private static boolean isRetryable(Exception e) {
        return HttpRetryHelper.isRetryable(e);
    }

    @Override
    public int estimateTokens(String text) {
        // P0-7: delegate to the shared CJK-aware default. Pre-P0-12 this
        // was {@code length/3.5}, which under-counted Chinese text by
        // 1.7–2.5× and caused the agent to blow past the model's context
        // window on CJK analyses.
        return LlmProvider.estimateTokensDefault(text);
    }

    @Override
    public boolean isAvailable() {
        return apiKey != null && !apiKey.isBlank();
    }

    @Override
    public void close() {
        HttpRetryHelper.closeHttpClient(httpClient);
    }
}
