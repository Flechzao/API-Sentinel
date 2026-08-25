package com.flechazo.apisentinel.intruder;

import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.GeneratedPayload;
import burp.api.montoya.intruder.IntruderInsertionPoint;
import burp.api.montoya.intruder.PayloadGenerator;
import com.flechazo.apisentinel.ai.prompt.IntruderPayloadPrompt;
import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmProviderFactory;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.util.HttpMessageUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI payload generator for Burp Intruder. For each insertion point it asks
 * the configured LLM for context-aware payloads (using the FULL request
 * template from {@link AttackConfiguration} — the context by-ai's reference
 * implementation ignored), caches the list and feeds Intruder one payload per
 * call until exhausted. Inspired by by-ai (MIT) — see docs/THIRD-PARTY.md.
 *
 * Intruder drains the generator when an attack starts, so the single blocking
 * LLM call happens once per insertion point at attack start, not per payload.
 */
public class AiPayloadGenerator implements PayloadGenerator {

    private static final int GENERATION_TIMEOUT_SEC = 45;
    private static final int MAX_PAYLOADS = 60;
    private static final int MAX_PAYLOAD_LEN = 2000;

    private static final Pattern NUMBERING = Pattern.compile("^\\s*(\\d+[.)、]|[-*•])\\s+");
    private static final Pattern PROSE_PREFIX = Pattern.compile(
            "^(注[：:]|说明[：:]|以下是|下面是|这是|Here|Note|payloads?\\s*[:：])");
    private static final Pattern PAYLOAD_CHARS = Pattern.compile("[<>'\"=\\\\$;|&{}]");

    private static boolean isProseLine(String line) {
        if (PROSE_PREFIX.matcher(line).find()) return true;
        // Lines ending in a colon with no payload-like special chars are
        // descriptive prose ("这是生成的载荷："), not payloads.
        if (line.endsWith("：") || line.endsWith(":")) {
            return !PAYLOAD_CHARS.matcher(line).find();
        }
        return false;
    }

    private final LlmProviderFactory providerFactory;
    private final LlmProvider directProvider; // test seam; null in production
    private final ConfigManager configManager;
    private final LeveledLogger logger;
    private final AttackConfiguration attackConfig;

    /** Per-insertion-point payload cache + cursor. */
    private final Map<String, List<String>> cache = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> cursors = new ConcurrentHashMap<>();

    public AiPayloadGenerator(LlmProviderFactory providerFactory, ConfigManager configManager,
                              LeveledLogger logger, AttackConfiguration attackConfig) {
        this(providerFactory, null, configManager, logger, attackConfig);
    }

    /** Test seam: inject a provider directly instead of going through the factory. */
    AiPayloadGenerator(LlmProviderFactory providerFactory, LlmProvider directProvider,
                       ConfigManager configManager, LeveledLogger logger, AttackConfiguration attackConfig) {
        this.providerFactory = providerFactory;
        this.directProvider = directProvider;
        this.configManager = configManager;
        this.logger = logger;
        this.attackConfig = attackConfig;
    }

    @Override
    public GeneratedPayload generatePayloadFor(IntruderInsertionPoint insertionPoint) {
        try {
            String baseValue = insertionPoint != null && insertionPoint.baseValue() != null
                    ? insertionPoint.baseValue().toString() : "";
            String next = nextPayloadFor(baseValue, requestTemplateContent());
            return next == null ? GeneratedPayload.end() : GeneratedPayload.payload(next);
        } catch (Exception e) {
            if (logger != null) logger.warn("[Intruder] 载荷生成异常: %s", e.getMessage());
            return GeneratedPayload.end();
        }
    }

    /** Pure core: next payload for an insertion point, or null when
     *  exhausted/unavailable. Montoya-free so it is unit-testable. */
    String nextPayloadFor(String baseValue, String rawRequest) {
        String key = cacheKey(baseValue, rawRequest);
        List<String> payloads = cache.computeIfAbsent(key,
                k -> generatePayloads(baseValue, rawRequest));
        if (payloads.isEmpty()) {
            return null;
        }
        int idx = cursors.computeIfAbsent(key, k -> new AtomicInteger(0)).getAndIncrement();
        return idx < payloads.size() ? payloads.get(idx) : null;
    }

    // ======================== generation ========================

    private List<String> generatePayloads(String baseValue, String rawRequest) {
        LlmProvider provider = directProvider != null
                ? directProvider
                : (providerFactory == null ? null : providerFactory.getFirstAvailable());
        if (provider == null) {
            if (logger != null) logger.warn("[Intruder] AI 未配置，无法生成载荷（设置 → AI 设置）");
            return List.of();
        }

        String[] meta = extractRequestMeta(rawRequest);
        String paramContext = findParamContext(rawRequest, baseValue);
        String oobDomain = oobDomainOrNull();

        String userPrompt = IntruderPayloadPrompt.buildUserPrompt(
                meta[0], meta[1], meta[2], paramContext, baseValue, oobDomain);
        try {
            LlmRequest request = new LlmRequest(
                    IntruderPayloadPrompt.getSystemPrompt(), userPrompt, 4096);
            LlmResponse response = provider.complete(request)
                    .get(GENERATION_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (!response.isSuccess()) {
                if (logger != null) logger.warn("[Intruder] AI 生成失败: %s", response.errorMessage());
                return List.of();
            }
            List<String> payloads = parsePayloadLines(response.content());
            if (logger != null) {
                logger.info("[Intruder] AI 生成 %d 个载荷（插入点当前值: %s）",
                        payloads.size(), baseValue.length() > 40 ? baseValue.substring(0, 40) + "…" : baseValue);
            }
            return payloads;
        } catch (Exception e) {
            if (logger != null) logger.warn("[Intruder] AI 调用异常/超时: %s", e.getMessage());
            return List.of();
        }
    }

    private String oobDomainOrNull() {
        try {
            var cfg = configManager.getConfig();
            if (cfg.isOobEnabled() && "internal".equals(cfg.getOobProvider())) {
                String base = cfg.getOobInternalBaseDomain();
                return base == null || base.isBlank() ? null : base;
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ======================== pure helpers (unit-testable) ========================

    /** Parse an LLM payload list: strip fences/numbering/prose/empties, dedup, cap. */
    public static List<String> parsePayloadLines(String content) {
        if (content == null || content.isBlank()) return List.of();
        List<String> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        boolean inFence = false;
        for (String rawLine : content.split("\n")) {
            String line = rawLine.trim();
            if (line.startsWith("```")) {
                inFence = !inFence;
                continue;
            }
            if (line.isEmpty()) continue;
            if (!inFence && isProseLine(line)) continue;
            String p = NUMBERING.matcher(line).replaceFirst("");
            if (p.isEmpty() || p.length() > MAX_PAYLOAD_LEN) continue;
            if (seen.add(p)) {
                out.add(p);
                if (out.size() >= MAX_PAYLOADS) break;
            }
        }
        return out;
    }

    /** [method, path+query, host] from a raw request ("" fallbacks). */
    public static String[] extractRequestMeta(String rawRequest) {
        if (rawRequest == null || rawRequest.isBlank()) return new String[]{"GET", "/", ""};
        String firstLine = rawRequest.split("\r?\n", 2)[0];
        String[] parts = firstLine.split(" ");
        String method = parts.length > 0 ? parts[0] : "GET";
        String path = parts.length > 1 ? parts[1] : "/";
        String host = HttpMessageUtils.getHeader(rawRequest, "Host");
        return new String[]{method, path, host == null ? "" : host};
    }

    /** Describe where the base value sits in the request (best effort —
     *  Montoya's IntruderInsertionPoint only exposes baseValue()). */
    public static String findParamContext(String rawRequest, String baseValue) {
        if (rawRequest == null || baseValue == null || baseValue.isEmpty()
                || !rawRequest.contains(baseValue)) {
            return "插入点位置: 未知（参数值未在请求模板中定位到）";
        }
        String headers = HttpMessageUtils.headerSection(rawRequest);
        boolean inHeaders = headers.contains(baseValue);

        if (!inHeaders) {
            // Body context: look for "key":"<value>" just before the base value.
            String body = HttpMessageUtils.bodyOf(rawRequest);
            int idx = body.indexOf(baseValue);
            if (idx > 0) {
                String before = body.substring(Math.max(0, idx - 60), idx);
                Matcher m = Pattern.compile("\"([\\w.-]+)\"\\s*:\\s*\"?$").matcher(before);
                if (m.find()) {
                    return "插入点位置: 请求体 JSON 字段 \"" + m.group(1) + "\"";
                }
                Matcher form = Pattern.compile("([\\w.-]+)=$").matcher(before);
                if (form.find()) {
                    return "插入点位置: 请求体表单参数 " + form.group(1);
                }
                return "插入点位置: 请求体";
            }
        }

        // Query / header / path context.
        String target = HttpMessageUtils.requestTarget(rawRequest);
        int qIdx = target.indexOf('?');
        if (qIdx >= 0) {
            String query = target.substring(qIdx + 1);
            int vIdx = query.indexOf(baseValue);
            if (vIdx > 0) {
                String before = query.substring(0, vIdx);
                Matcher m = Pattern.compile("(?:^|&)([\\w.-]+)=$").matcher(before);
                if (m.find()) {
                    return "插入点位置: URL 查询参数 " + m.group(1);
                }
                return "插入点位置: URL 查询串";
            }
        }
        if (inHeaders) {
            for (String line : headers.split("\r?\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(colon).contains(baseValue)) {
                    return "插入点位置: 请求头 " + line.substring(0, colon).trim();
                }
            }
            return "插入点位置: 请求头";
        }
        return "插入点位置: URL 路径";
    }

    // ======================== plumbing ========================

    private String requestTemplateContent() {
        try {
            if (attackConfig != null && attackConfig.requestTemplate() != null
                    && attackConfig.requestTemplate().content() != null) {
                byte[] bytes = attackConfig.requestTemplate().content().getBytes();
                return new String(bytes, StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static String cacheKey(String baseValue, String rawRequest) {
        int reqHash = rawRequest == null ? 0 : rawRequest.hashCode();
        return baseValue + "|" + Integer.toHexString(reqHash);
    }
}
