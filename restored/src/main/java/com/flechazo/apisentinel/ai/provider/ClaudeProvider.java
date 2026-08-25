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
 * Claude (Anthropic) LLM Provider——支持扩展思考、工具调用、Beta interleaved thinking。
 */
public class ClaudeProvider implements LlmProvider {

    private static final Gson GSON = new Gson();
    private volatile String endpoint = "https://api.anthropic.com";
    private volatile String apiKey = "";
    private volatile String model = "claude-sonnet-4-20250514";
    private final HttpClient httpClient;
    private volatile java.util.concurrent.ExecutorService executor;

    public ClaudeProvider() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    public void setExecutor(java.util.concurrent.ExecutorService executor) {
        this.executor = executor;
    }

    @Override
    public String getId() { return "claude"; }

    @Override
    public String getDisplayName() { return "Claude (Anthropic)"; }

    @Override
    public boolean supportsToolCalling() { return true; }

    @Override
    public boolean supportsExtendedThinking() { return true; }

    /** Anthropic beta header enabling the model to think again after each
     *  tool result within an ongoing agentic turn, instead of only once at
     *  the very start — matches this codebase's "one HTTP call per ReAct
     *  iteration" loop shape (AgentLoop), where each iteration reads the
     *  previous tool result and decides the next action. */
    private static final String INTERLEAVED_THINKING_BETA = "interleaved-thinking-2025-05-14";
    /** Anthropic requires budget_tokens to leave room for the actual
     *  response; keep at least this many tokens free above the thinking budget. */
    private static final int THINKING_MIN_BUDGET = 1024;
    private static final int THINKING_OUTPUT_HEADROOM = 1024;

    /** Extended thinking launched with the 3.7/4.x generation; older models
     *  (3 and 3.5) reject the "thinking" request field. Not an exhaustive
     *  allowlist — newer/unrecognized model strings default to "supported"
     *  and the one-shot 400 fallback in {@link #doComplete} covers surprises. */
    private static boolean modelSupportsThinking(String model) {
        if (model == null || model.isBlank()) return true;
        String m = model.toLowerCase(java.util.Locale.ROOT);
        return !(m.contains("claude-3-opus") || m.contains("claude-3-sonnet")
                || m.contains("claude-3-haiku") || m.contains("claude-3-5"));
    }

    /** Resolves the effective thinking budget for this request, or null when
     *  thinking should not be requested (not asked for, model incompatible,
     *  or too little room left under max_tokens). */
    private Integer resolveThinkingBudget(LlmRequest request) {
        Integer requested = request.thinkingBudgetTokens();
        if (requested == null || requested <= 0) return null;
        if (!modelSupportsThinking(effectiveModel(request))) return null;
        int clamped = Math.min(requested, request.maxTokens() - THINKING_OUTPUT_HEADROOM);
        return clamped >= THINKING_MIN_BUDGET ? clamped : null;
    }

    @Override
    public void configure(String endpoint, String apiKey, String model) {
        if (endpoint != null && !endpoint.isBlank()) {
            this.endpoint = endpoint.replaceAll("/v1/messages$", "").replaceAll("/$", "");
        }
        if (apiKey != null && !apiKey.isBlank()) this.apiKey = apiKey;
        if (model != null && !model.isBlank()) this.model = model;
    }

    private String getMessagesUrl() {
        return endpoint + "/v1/messages";
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
        Integer thinkingBudget = resolveThinkingBudget(request);
        // One-shot fallback: if a thinking-enabled call is rejected with 400
        // (e.g. an account/model combination that unexpectedly doesn't support
        // it), retry exactly once with thinking turned off rather than failing
        // the whole analysis step outright.
        boolean thinkingFallbackUsed = false;

        for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            try {
                if (attempt > 0) {
                    Thread.sleep(3000L * attempt);
                }

                JsonObject body = buildRequestBody(request, thinkingBudget);

                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(getMessagesUrl()))
                        .timeout(Duration.ofSeconds(180))
                        .header("Content-Type", "application/json")
                        .header("x-api-key", apiKey)
                        .header("anthropic-version", "2023-06-01");
                if (thinkingBudget != null) {
                    reqBuilder.header("anthropic-beta", INTERLEAVED_THINKING_BETA);
                }
                HttpRequest httpReq = reqBuilder
                        .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)))
                        .build();

                HttpResponse<String> resp = httpClient.send(httpReq, HttpResponse.BodyHandlers.ofString());
                long latency = System.currentTimeMillis() - start;

                if (resp.statusCode() == 400 && thinkingBudget != null && !thinkingFallbackUsed) {
                    thinkingFallbackUsed = true;
                    thinkingBudget = null;
                    continue; // retry this same attempt slot without thinking
                }
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
                    return LlmResponse.error("Claude API returned " + resp.statusCode() + ": " + truncateBody(resp.body()));
                }
                if (resp.statusCode() != 200) {
                    return LlmResponse.error("Claude API returned " + resp.statusCode() + ": " + truncateBody(resp.body()));
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

    private JsonObject buildRequestBody(LlmRequest request, Integer thinkingBudget) {
        JsonObject body = new JsonObject();
        body.addProperty("model", effectiveModel(request));
        body.addProperty("max_tokens", request.maxTokens());
        // Anthropic requires temperature == 1 whenever extended thinking is
        // enabled (any other value is rejected with a 400).
        body.addProperty("temperature", thinkingBudget != null ? 1.0 : request.temperature());

        if (thinkingBudget != null) {
            JsonObject thinking = new JsonObject();
            thinking.addProperty("type", "enabled");
            thinking.addProperty("budget_tokens", thinkingBudget);
            body.add("thinking", thinking);
        }

        if (request.isMultiTurn()) {
            buildMultiTurnBody(body, request);
        } else {
            buildSingleTurnBody(body, request);
        }

        if (request.hasTools()) {
            JsonArray toolsArray = new JsonArray();
            for (ToolDefinition td : request.tools()) {
                JsonObject tool = new JsonObject();
                tool.addProperty("name", td.name());
                tool.addProperty("description", td.description());
                tool.add("input_schema", td.inputSchema());
                toolsArray.add(tool);
            }
            body.add("tools", toolsArray);
        }

        // Claude has no native response_format; force JSON output via the
        // system prompt so downstream JSON parsing doesn't have to salvage
        // markdown-wrapped or free-text responses.
        if ("json".equals(request.responseFormat())) {
            JsonElement sysEl = body.get("system");
            String sys = (sysEl != null && sysEl.isJsonPrimitive()) ? sysEl.getAsString() : "";
            String jsonInstr = "\n\nIMPORTANT: You must respond with a single valid JSON object only. "
                    + "Do not wrap it in markdown code fences. Do not add any prose before or after.";
            body.addProperty("system", (sys == null ? "" : sys) + jsonInstr);
        }

        return body;
    }

    private void buildSingleTurnBody(JsonObject body, LlmRequest request) {
        if (request.systemPrompt() != null && !request.systemPrompt().isEmpty()) {
            body.addProperty("system", request.systemPrompt());
        }
        JsonArray messages = new JsonArray();
        JsonObject userMsg = new JsonObject();
        userMsg.addProperty("role", "user");
        userMsg.addProperty("content", request.userPrompt());
        messages.add(userMsg);
        body.add("messages", messages);
    }

    private void buildMultiTurnBody(JsonObject body, LlmRequest request) {
        JsonArray messages = new JsonArray();
        JsonArray pendingToolResults = null;

        for (ChatMessage msg : request.messages()) {
            if ("system".equals(msg.role())) {
                body.addProperty("system", msg.content());
                continue;
            }

            if ("tool".equals(msg.role())) {
                if (pendingToolResults == null) {
                    pendingToolResults = new JsonArray();
                }
                JsonObject toolResult = new JsonObject();
                toolResult.addProperty("type", "tool_result");
                toolResult.addProperty("tool_use_id", msg.toolCallId());
                toolResult.addProperty("content", msg.content());
                pendingToolResults.add(toolResult);
                continue;
            }

            // Flush any pending tool results before adding a non-tool message
            if (pendingToolResults != null) {
                JsonObject userMsg = new JsonObject();
                userMsg.addProperty("role", "user");
                userMsg.add("content", pendingToolResults);
                messages.add(userMsg);
                pendingToolResults = null;
            }

            if ("assistant".equals(msg.role()) && msg.hasToolCalls()) {
                // Assistant message with tool calls — build content blocks
                JsonObject assistantMsg = new JsonObject();
                assistantMsg.addProperty("role", "assistant");
                JsonArray contentBlocks = new JsonArray();
                // Thinking blocks must be echoed back verbatim (including their
                // opaque signature/data fields) and must come first — Anthropic
                // requires this when continuing a turn that used extended
                // thinking together with tool use.
                if (msg.rawThinkingBlocksJson() != null && !msg.rawThinkingBlocksJson().isBlank()) {
                    try {
                        JsonArray thinkingBlocks = GSON.fromJson(msg.rawThinkingBlocksJson(), JsonArray.class);
                        if (thinkingBlocks != null) {
                            for (JsonElement tb : thinkingBlocks) contentBlocks.add(tb);
                        }
                    } catch (Exception ignored) {
                        // Malformed/legacy stored blocks — skip rather than corrupt the request.
                    }
                }
                if (msg.content() != null && !msg.content().isEmpty()) {
                    JsonObject textBlock = new JsonObject();
                    textBlock.addProperty("type", "text");
                    textBlock.addProperty("text", msg.content());
                    contentBlocks.add(textBlock);
                }
                for (ToolCall tc : msg.toolCalls()) {
                    JsonObject toolUse = new JsonObject();
                    toolUse.addProperty("type", "tool_use");
                    toolUse.addProperty("id", tc.id());
                    toolUse.addProperty("name", tc.toolName());
                    toolUse.add("input", GSON.fromJson(tc.arguments(), JsonObject.class));
                    contentBlocks.add(toolUse);
                }
                assistantMsg.add("content", contentBlocks);
                messages.add(assistantMsg);
                continue;
            }

            // Regular user/assistant text message
            JsonObject m = new JsonObject();
            m.addProperty("role", msg.role());
            m.addProperty("content", msg.content() != null ? msg.content() : "");
            messages.add(m);
        }

        // Flush any remaining tool results
        if (pendingToolResults != null) {
            JsonObject userMsg = new JsonObject();
            userMsg.addProperty("role", "user");
            userMsg.add("content", pendingToolResults);
            messages.add(userMsg);
        }

        body.add("messages", messages);
    }

    private LlmResponse parseResponse(String responseBody, long latency) {
        JsonObject result = GSON.fromJson(responseBody, JsonObject.class);

        if (!result.has("content")) {
            String errType = result.has("error") ? result.getAsJsonObject("error").get("message").getAsString() : "未知错误";
            return LlmResponse.error("Claude API 错误: " + errType);
        }

        JsonArray content = result.getAsJsonArray("content");

        int inputTokens = 0;
        int outputTokens = 0;
        if (result.has("usage") && !result.get("usage").isJsonNull()) {
            JsonObject usage = result.getAsJsonObject("usage");
            if (usage.has("input_tokens")) inputTokens = usage.get("input_tokens").getAsInt();
            if (usage.has("output_tokens")) outputTokens = usage.get("output_tokens").getAsInt();
        }

        String stopReason = "end_turn";
        if (result.has("stop_reason") && !result.get("stop_reason").isJsonNull()) {
            stopReason = result.get("stop_reason").getAsString();
        }

        StringBuilder textContent = new StringBuilder();
        StringBuilder thinkingText = new StringBuilder();
        JsonArray thinkingBlocks = new JsonArray();
        List<ToolCall> toolCalls = new ArrayList<>();

        for (JsonElement block : content) {
            JsonObject b = block.getAsJsonObject();
            String type = b.get("type").getAsString();
            if ("text".equals(type)) {
                textContent.append(b.get("text").getAsString());
            } else if ("tool_use".equals(type)) {
                String id = b.get("id").getAsString();
                String name = b.get("name").getAsString();
                String args = GSON.toJson(b.get("input"));
                toolCalls.add(new ToolCall(id, name, args));
            } else if ("thinking".equals(type)) {
                if (b.has("thinking")) thinkingText.append(b.get("thinking").getAsString());
                thinkingBlocks.add(b); // preserved verbatim, including "signature"
            } else if ("redacted_thinking".equals(type)) {
                // Content is encrypted/opaque ("data" field) — nothing readable
                // to surface, but must still be echoed back verbatim next turn.
                thinkingBlocks.add(b);
            }
        }

        LlmResponse.FinishReason reason;
        if ("tool_use".equals(stopReason)) {
            reason = LlmResponse.FinishReason.TOOL_USE;
        } else if ("max_tokens".equals(stopReason)) {
            reason = LlmResponse.FinishReason.MAX_TOKENS;
        } else {
            reason = LlmResponse.FinishReason.COMPLETE;
        }

        String thinkingTextOut = thinkingText.length() > 0 ? thinkingText.toString() : null;
        String rawThinkingBlocksJson = !thinkingBlocks.isEmpty() ? thinkingBlocks.toString() : null;

        return new LlmResponse(textContent.toString(), inputTokens, outputTokens,
                latency, model, reason, null, toolCalls.isEmpty() ? null : toolCalls,
                thinkingTextOut, rawThinkingBlocksJson);
    }

    private static long computeBackoffMs(HttpResponse<String> resp, int attempt) {
        // Honor Retry-After (seconds). Claude also sends anthropic-ratelimit-reset
        // but that's a timestamp; fall back to exponential backoff if unparseable.
        String ra = resp.headers().firstValue("retry-after").orElse(null);
        if (ra != null) {
            try {
                long ms = Long.parseLong(ra.trim()) * 1000L;
                if (ms > 0) return Math.min(ms, 30000L);
            } catch (NumberFormatException ignored) { /* HTTP-date form, fall back */ }
        }
        // Exponential: attempt 0 -> 2s, 1 -> 4s, capped at 30s
        return Math.min(2000L * (1L << attempt), 30000L);
    }

    private static String truncateBody(String body) {
        if (body == null) return "";
        return body.length() <= 500 ? body : body.substring(0, 500) + "...";
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
        return (int) (text.length() / 3.5);
    }

    @Override
    public boolean isAvailable() {
        return apiKey != null && !apiKey.isBlank();
    }
}
