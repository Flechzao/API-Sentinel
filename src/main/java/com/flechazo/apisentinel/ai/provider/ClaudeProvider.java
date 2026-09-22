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

    /** Visible-for-testing only. Normal callers go through {@link #complete(LlmRequest)}. */
    JsonObject buildRequestBody(LlmRequest request, Integer thinkingBudget) {
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
            // Prompt-caching breakpoint #1: cache the full tool catalog on
            // the LAST tool definition. Tools are stable within a phase, so
            // across an Agent run's iterations the ~3-8K tokens of tool
            // schemas hit the 1h cache instead of being re-billed every turn.
            if (request.isMultiTurn() && !toolsArray.isEmpty()) {
                attachEphemeralCacheControl(toolsArray, toolsArray.size() - 1);
            }
            body.add("tools", toolsArray);
        }

        // Claude has no native response_format; force JSON output via the
        // system prompt so downstream JSON parsing doesn't have to salvage
        // markdown-wrapped or free-text responses.
        if ("json".equals(request.responseFormat())) {
            appendJsonFormatInstruction(body);
        }

        // Prompt-caching breakpoint #2: convert the (merged-by-P0-1) system
        // string into the content-block array form and mark the first block
        // with cache_control. The main prompt is the stable portion (~5K tokens
        // of SafetyRules / tool rules / GoT / analysis strategy), while
        // dynamic injections (reflection, findings, validation) land after
        // it in the same buffer. Because P0-1 keeps the buffer's prefix
        // stable across iterations, the cache actually hits on turn 2+.
        if (request.isMultiTurn() && body.has("system") && body.get("system").isJsonPrimitive()) {
            body.add("system", wrapSystemAsCachedBlocks(body.get("system").getAsString()));
        }

        // Prompt-caching breakpoint #3: cache everything up to and including
        // the last user message. Each turn the cache grows by one assistant+user
        // pair; the next turn reads all of it and only pays for the new pair.
        if (request.isMultiTurn() && body.has("messages") && body.get("messages").isJsonArray()) {
            JsonArray msgs = body.getAsJsonArray("messages");
            if (!msgs.isEmpty()) {
                attachEphemeralCacheControl(msgs, msgs.size() - 1);
            }
        }

        return body;
    }

    /** Appends the JSON-only formatting hint to whatever system prompt is
     *  already on the body, regardless of whether it's a plain string or
     *  the new content-block array form. Kept as a separate step so the
     *  cache-control marking (which runs after this) sees the final text. */
    private static void appendJsonFormatInstruction(JsonObject body) {
        String jsonInstr = "IMPORTANT: You must respond with a single valid JSON object only. "
                + "Do not wrap it in markdown code fences. Do not add any prose before or after.";
        if (!body.has("system")) {
            body.addProperty("system", jsonInstr);
            return;
        }
        if (body.get("system").isJsonPrimitive()) {
            String sys = body.get("system").getAsString();
            body.addProperty("system", sys + "\n\n" + jsonInstr);
            return;
        }
        // Already converted to a content-block array — append to the last text block.
        JsonArray blocks = body.getAsJsonArray("system");
        if (blocks == null || blocks.isEmpty()) {
            body.addProperty("system", jsonInstr);
            return;
        }
        JsonObject last = blocks.get(blocks.size() - 1).getAsJsonObject();
        if (last != null && last.has("text") && last.get("text").isJsonPrimitive()) {
            last.addProperty("text", last.get("text").getAsString() + "\n\n" + jsonInstr);
        } else {
            JsonObject extra = new JsonObject();
            extra.addProperty("type", "text");
            extra.addProperty("text", jsonInstr);
            blocks.add(extra);
        }
    }

    /** Converts a merged system string into the content-block array form
     *  Anthropic's prompt-caching API requires, and marks the first block
     *  with {@code cache_control: {"type": "ephemeral"}}. We split on the
     *  P0-1 separator ("\n\n") so the stable main prompt becomes one block
     *  (the cached one) and each dynamic injection becomes its own block
     *  afterwards — this way the cache hit rate isn't disturbed when the
     *  injections change content between turns. */
    private static JsonArray wrapSystemAsCachedBlocks(String merged) {
        JsonArray blocks = new JsonArray();
        if (merged == null || merged.isEmpty()) return blocks;
        String[] parts = merged.split("\n\n", -1);
        for (int i = 0; i < parts.length; i++) {
            JsonObject block = new JsonObject();
            block.addProperty("type", "text");
            block.addProperty("text", parts[i]);
            if (i == 0) {
                // First block = the stable main prompt. Mark it so the
                // 1h TTL cache actually latches onto it across turns.
                JsonObject cc = new JsonObject();
                cc.addProperty("type", "ephemeral");
                block.add("cache_control", cc);
            }
            blocks.add(block);
        }
        return blocks;
    }

    /** Adds {@code cache_control: {"type": "ephemeral"}} to the JSON object
     *  at {@code index} in {@code array}. Silently no-ops if the element at
     *  that index isn't an object (defensive — e.g. a future call site that
     *  passes a primitive array shouldn't crash). */
    private static void attachEphemeralCacheControl(JsonArray array, int index) {
        if (array == null || index < 0 || index >= array.size()) return;
        if (!array.get(index).isJsonObject()) return;
        JsonObject target = array.get(index).getAsJsonObject();
        JsonObject cc = new JsonObject();
        cc.addProperty("type", "ephemeral");
        target.add("cache_control", cc);
    }

    /** Visible-for-testing only. Normal callers go through {@link #complete(LlmRequest)}. */
    void buildSingleTurnBody(JsonObject body, LlmRequest request) {
        // Collect any system-role entries from the message list (defensive:
        // single-turn normally carries its prompt via request.systemPrompt()
        // set below, but some callers also add ChatMessage.system(...) directly).
        // Concatenate in arrival order so the main prompt always precedes any
        // dynamic injection (reflection / findings / validation summary).
        StringBuilder systemBuf = new StringBuilder();
        if (request.systemPrompt() != null && !request.systemPrompt().isEmpty()) {
            systemBuf.append(request.systemPrompt());
        }
        JsonArray messages = new JsonArray();
        for (ChatMessage msg : request.messages() != null ? request.messages() : java.util.List.<ChatMessage>of()) {
            if ("system".equals(msg.role())) {
                if (!systemBuf.isEmpty()) systemBuf.append("\n\n");
                systemBuf.append(msg.content() != null ? msg.content() : "");
            } else {
                JsonObject m = new JsonObject();
                m.addProperty("role", msg.role());
                m.addProperty("content", msg.content());
                messages.add(m);
            }
        }
        // Fallback: if no system messages came from the message list, add a
        // single user turn so the request is still well-formed.
        if (messages.size() == 0) {
            JsonObject userMsg = new JsonObject();
            userMsg.addProperty("role", "user");
            userMsg.addProperty("content", request.userPrompt() != null ? request.userPrompt() : "");
            messages.add(userMsg);
        }
        if (!systemBuf.isEmpty()) {
            body.addProperty("system", systemBuf.toString());
        }
        body.add("messages", messages);
    }

    /** Visible-for-testing only. Normal callers go through {@link #complete(LlmRequest)}. */
    void buildMultiTurnBody(JsonObject body, LlmRequest request) {
        // Single-system principle (P0-1 fix): pre-2026-09-06 the loop below
        // called body.addProperty("system", msg.content()) for every system
        // message, and Gson's JsonObject overwrites duplicate keys — so in
        // a 20-iteration Agent run the original 5.2K main system prompt
        // (SafetyRules, tool-use rules, GoT, analysis strategy) was silently
        // evicted by the last reflection/findings/validation injection.
        //
        // Fix: accumulate every system-role message into a single buffer,
        // in the order they appear in the message list (which is the order
        // AgentLoop appends: main prompt first, then dynamic injections).
        // We also prepend request.systemPrompt() so callers that set the
        // prompt via the request field (instead of a ChatMessage.system
        // entry) still land at the front.
        StringBuilder systemBuf = new StringBuilder();
        if (request.systemPrompt() != null && !request.systemPrompt().isEmpty()) {
            systemBuf.append(request.systemPrompt());
        }

        JsonArray messages = new JsonArray();
        JsonArray pendingToolResults = null;

        for (ChatMessage msg : request.messages()) {
            if ("system".equals(msg.role())) {
                if (!systemBuf.isEmpty()) systemBuf.append("\n\n");
                systemBuf.append(msg.content() != null ? msg.content() : "");
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

        // Write the merged system prompt ONCE, after the loop — so the main
        // prompt + all dynamic injections survive together.
        if (!systemBuf.isEmpty()) {
            body.addProperty("system", systemBuf.toString());
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
        int cacheCreation = 0;
        int cacheRead = 0;
        if (result.has("usage") && !result.get("usage").isJsonNull()) {
            JsonObject usage = result.getAsJsonObject("usage");
            if (usage.has("input_tokens")) inputTokens = usage.get("input_tokens").getAsInt();
            if (usage.has("output_tokens")) outputTokens = usage.get("output_tokens").getAsInt();
            // Prompt-caching accounting: Anthropic reports cache write/read
            // as separate fields. input_tokens EXCLUDES both, so the true
            // billable input is input_tokens + cache_creation + cache_read.
            if (usage.has("cache_creation_input_tokens")) {
                cacheCreation = usage.get("cache_creation_input_tokens").getAsInt();
            }
            if (usage.has("cache_read_input_tokens")) {
                cacheRead = usage.get("cache_read_input_tokens").getAsInt();
            }
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
                thinkingTextOut, rawThinkingBlocksJson, cacheCreation, cacheRead);
    }

    // Retry helpers delegated to shared HttpRetryHelper (was duplicated
    // across ClaudeProvider / OpenAiProvider / OllamaProvider).
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
