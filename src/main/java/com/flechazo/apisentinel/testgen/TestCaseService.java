package com.flechazo.apisentinel.testgen;

import com.flechazo.apisentinel.ai.analysis.VulnFinding;
import com.flechazo.apisentinel.ai.prompt.TestGenPrompt;
import com.flechazo.apisentinel.ai.prompt.UntrustedContent;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class TestCaseService {

    private final LlmProvider provider;
    private final LeveledLogger logger;
    /** Optional low-cost model override for payload generation (cost tiering).
     *  Null/blank = use the provider's main model. */
    private final String modelOverride;
    private static final Gson GSON = new Gson();

    public TestCaseService(LlmProvider provider, LeveledLogger logger) {
        this(provider, logger, null);
    }

    public TestCaseService(LlmProvider provider, LeveledLogger logger, String modelOverride) {
        this.provider = provider;
        this.logger = logger;
        this.modelOverride = modelOverride;
    }

    /**
     * Detailed result of a test-case generation attempt, preserving the AI's stated
     * reasoning and any failure diagnostics so callers can surface "why" instead of
     * silently swallowing an empty result.
     */
    public record TestGenResult(List<TestCase> cases, String reasoning, String rawResponse, String errorReason) {
        public boolean isSuccess() { return errorReason == null || errorReason.isEmpty(); }
    }

    /**
     * Simple generation without Stage 1 findings (backward-compatible).
     */
    public CompletableFuture<List<TestCase>> generate(String method, String path,
                                                       String host, String parameters,
                                                       String sourceCode) {
        return generateDetailed(method, path, host, parameters, sourceCode, List.of())
                .thenApply(TestGenResult::cases);
    }

    /**
     * Detailed generation without Stage 1 findings (backward-compatible).
     */
    public CompletableFuture<TestGenResult> generateDetailed(String method, String path,
                                                              String host, String parameters,
                                                              String sourceCode) {
        return generateDetailed(method, path, host, parameters, sourceCode, List.of());
    }

    /**
     * Detailed generation WITH Stage 1 findings to guide payload focus.
     */
    public CompletableFuture<TestGenResult> generateDetailed(String method, String path,
                                                              String host, String parameters,
                                                              String sourceCode,
                                                              List<VulnFinding> stage1Findings) {
        // P2-4: mint one nonce fence for the Stage-3 run; system prompt's
        // fence instruction and the user prompt's attacker-controlled blocks
        // (parameters, Stage-1 findings evidence, source code) share it so a
        // Stage-1 evidence snippet that quoted target-response bytes can't
        // re-inject into payload generation.
        UntrustedContent fence = UntrustedContent.forRun();
        String systemPrompt = TestGenPrompt.getSystemPrompt(fence);
        String userPrompt = TestGenPrompt.buildUserPrompt(fence, method, path, host, parameters, sourceCode, stage1Findings);

        // 4096 was tight enough that generating the requested 2-5 test cases
        // (11 fields each) sometimes left the last one or two with visibly
        // thin/empty content — not necessarily hard JSON truncation (GSON
        // would reject genuinely malformed JSON outright, surfacing as
        // errorReason below, not a silent partial list), but the model
        // running low on its own token budget mid-generation and filling in
        // trailing entries with empty-ish placeholder values. 8192 matches
        // AgentLoop's own per-turn budget, giving real headroom.
        LlmRequest request = new LlmRequest(systemPrompt, userPrompt, 8192);
        if (modelOverride != null && !modelOverride.isBlank()) {
            request = request.withModelOverride(modelOverride);
        }

        return provider.complete(request).thenApply(response -> {
            if (!response.isSuccess()) {
                logger.error("测试用例生成失败: %s", response.errorMessage());
                return new TestGenResult(List.of(), "", "", "AI 调用失败: " + response.errorMessage());
            }

            String json = extractJsonString(response.content());
            if (json == null) {
                logger.warn("测试用例响应非 JSON 格式");
                return new TestGenResult(List.of(), "", response.content(),
                        "AI 返回内容不是合法的 JSON 格式，无法解析");
            }

            try {
                JsonObject root = GSON.fromJson(json, JsonObject.class);
                String reasoning = getStr(root, "reasoning");
                List<TestCase> cases = parseTestCases(root);
                return new TestGenResult(cases, reasoning, response.content(), null);
            } catch (Exception e) {
                logger.error("解析测试用例 JSON 失败: %s", e.getMessage());
                return new TestGenResult(List.of(), "", response.content(),
                        "解析 AI 返回的 JSON 时出错: " + e.getMessage());
            }
        });
    }

    private List<TestCase> parseTestCases(JsonObject root) {
        List<TestCase> cases = new ArrayList<>();
        JsonArray arr = root.getAsJsonArray("test_cases");
        if (arr == null) return cases;

        for (var elem : arr) {
            JsonObject obj = elem.getAsJsonObject();
            Map<String, String> headers = new HashMap<>();
            if (obj.has("headers") && obj.get("headers").isJsonObject()) {
                obj.getAsJsonObject("headers").entrySet().forEach(e ->
                        headers.put(e.getKey(), e.getValue().getAsString()));
            }

            TestCase tc = new TestCase(
                    getStr(obj, "name"),
                    getStr(obj, "category"),
                    getStr(obj, "target_param"),
                    getStr(obj, "payload"),
                    getStr(obj, "method"),
                    getStr(obj, "path"),
                    headers,
                    getStr(obj, "body"),
                    getStr(obj, "description"),
                    getStr(obj, "expected_if_vulnerable"),
                    getStr(obj, "risk_if_confirmed")
            );
            // getStr() silently defaults missing/null fields to "" — nothing
            // downstream (GeneratePayloadsTool, RepeaterPanel.doLoadTestCases)
            // filters that out, so a low-content trailing entry (model ran low
            // on ideas/budget generating the requested batch) rendered as a
            // blank row in the Repeater's test-case table. Name+category+
            // payload all empty is not a usable test case under any target
            // language/style, so drop it here at the source instead of every
            // downstream consumer needing its own guard.
            if (tc.name().isEmpty() && tc.category().isEmpty() && tc.payload().isEmpty()) {
                logger.debug("跳过一个字段几乎全空的无效测试用例条目");
                continue;
            }
            cases.add(tc);
        }
        return cases;
    }

    private String getStr(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : "";
    }

    private String extractJsonString(String raw) {
        if (raw == null) return null;
        raw = raw.trim();
        // Direct JSON
        if (raw.startsWith("{")) return raw;
        // ```json ... ```
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "```(?:json)?\\s*\\n?(\\{.*?})\\s*```", java.util.regex.Pattern.DOTALL).matcher(raw);
        if (m.find()) return m.group(1);
        // First { to last }
        int start = raw.indexOf('{');
        int end = raw.lastIndexOf('}');
        if (start >= 0 && end > start) return raw.substring(start, end + 1);
        return null;
    }
}
