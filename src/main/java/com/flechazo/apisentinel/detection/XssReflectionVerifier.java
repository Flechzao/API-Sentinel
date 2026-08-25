package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.HttpMessageUtils;

import java.util.Locale;

/** XSS 反射验证器——canary 注入 + 标签探针 + 上下文分类。 */
public class XssReflectionVerifier {

    public enum ReflectionContext {
        NOT_REFLECTED,
        IN_HTML,
        IN_ATTRIBUTE,
        IN_SCRIPT,
        IN_JSON,
        ENCODED
    }

    public record XssReflectionResult(
            boolean reflected,
            boolean unfiltered,
            ReflectionContext context,
            boolean wafBlocked,
            String detail,
            String sentRequest,
            String receivedResponse,
            int statusCode,
            long elapsedMs
    ) {
        public static XssReflectionResult notReflected(String detail) {
            return new XssReflectionResult(false, false, ReflectionContext.NOT_REFLECTED,
                    false, detail, null, null, 0, 0);
        }
    }

    private final MontoyaApi api;
    private final LeveledLogger logger;
    private final WafDetector wafDetector;
    private final boolean wafDetectionEnabled;

    public XssReflectionVerifier(MontoyaApi api, LeveledLogger logger, boolean wafDetectionEnabled) {
        this.api = api;
        this.logger = logger;
        this.wafDetector = new WafDetector(logger);
        this.wafDetectionEnabled = wafDetectionEnabled;
    }

    public XssReflectionResult verify(ApiEntry entry, String paramName,
                                      String paramLocation, String paramValue) {
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty()) {
            return XssReflectionResult.notReflected("无捕获请求，无法验证");
        }

        // Phase 1: inject alphanumeric canary (no special chars → won't trigger WAF)
        String canary = generateCanary();
        String mutated = BlindParamMutator.mutate(raw, paramName, paramLocation, canary);
        if (mutated == null) {
            return XssReflectionResult.notReflected("无法在 " + paramLocation + " 定位参数 " + paramName);
        }

        Probe p1 = send(entry, mutated);
        if (p1 == null) {
            return XssReflectionResult.notReflected("canary 探针请求失败");
        }
        if (isWafBlocked(p1)) {
            return new XssReflectionResult(false, false, ReflectionContext.NOT_REFLECTED, true,
                    "canary 探针被 WAF 拦截", p1.rawRequest, p1.rawResponse, p1.status, p1.elapsed);
        }

        String body = HttpMessageUtils.bodyOf(p1.rawResponse);
        if (!body.contains(canary)) {
            return new XssReflectionResult(false, false, ReflectionContext.NOT_REFLECTED, false,
                    "canary 未在响应中反射", p1.rawRequest, p1.rawResponse, p1.status, p1.elapsed);
        }

        // Canary reflected — classify context
        ReflectionContext ctx = classifyContext(p1.rawResponse, canary);

        // Phase 2: inject angle-bracket probe to test if HTML chars are escaped
        String tagProbe = "<" + canary + ">";
        String mutated2 = BlindParamMutator.mutate(raw, paramName, paramLocation, tagProbe);
        if (mutated2 == null) {
            return new XssReflectionResult(true, false, ctx, false,
                    "参数反射 (context: " + ctx + ") 但无法注入标签探针",
                    p1.rawRequest, p1.rawResponse, p1.status, p1.elapsed);
        }

        Probe p2 = send(entry, mutated2);
        if (p2 == null || isWafBlocked(p2)) {
            return new XssReflectionResult(true, false, ctx, p2 != null && isWafBlocked(p2),
                    "参数反射 (context: " + ctx + "), 标签探针" + (p2 == null ? "请求失败" : "被WAF拦截"),
                    p1.rawRequest, p1.rawResponse, p1.status, p1.elapsed);
        }

        String body2 = HttpMessageUtils.bodyOf(p2.rawResponse);
        boolean unfiltered = body2.contains(tagProbe);
        String detail = unfiltered
                ? "XSS 确认: <" + canary + "> 在响应中原样反射 (context: " + ctx + ")"
                : "参数反射但尖括号被编码/过滤 (context: " + ctx + ")";

        if (unfiltered && logger != null) {
            logger.info("[XSS] %s 参数 %s 确认反射型 XSS: %s",
                    entry.getApiPath(), paramName, detail);
        }

        return new XssReflectionResult(true, unfiltered, ctx, false, detail,
                p2.rawRequest, p2.rawResponse, p2.status, p2.elapsed);
    }

    static String generateCanary() {
        long t = System.nanoTime();
        return "apsen" + Long.toHexString(t & 0xFFFFF);
    }

    public static ReflectionContext classifyContext(String rawResponse, String canary) {
        String body = HttpMessageUtils.bodyOf(rawResponse);
        if (!body.contains(canary)) return ReflectionContext.NOT_REFLECTED;

        String lower = body.toLowerCase(Locale.ROOT);
        int idx = body.indexOf(canary);

        // Check if inside <script> block
        int scriptStart = lower.lastIndexOf("<script", idx);
        int scriptEnd = lower.lastIndexOf("</script", idx);
        if (scriptStart >= 0 && (scriptEnd < 0 || scriptEnd < scriptStart)) {
            return ReflectionContext.IN_SCRIPT;
        }

        // Check if inside HTML attribute (look for preceding quote + =)
        int lineStart = body.lastIndexOf('\n', idx);
        String prefix = body.substring(Math.max(0, lineStart), idx);
        if (prefix.matches("(?s).*=\\s*[\"'][^\"']*$")) {
            return ReflectionContext.IN_ATTRIBUTE;
        }

        // Check if JSON response
        String contentType = extractContentType(rawResponse);
        if (contentType.contains("json")) {
            return ReflectionContext.IN_JSON;
        }

        // Check if HTML-entity encoded form is present instead of raw
        String encoded = canary.replace("<", "&lt;").replace(">", "&gt;");
        if (body.contains("&lt;" + canary) || body.contains(encoded)) {
            return ReflectionContext.ENCODED;
        }

        return ReflectionContext.IN_HTML;
    }

    private static String extractContentType(String rawResponse) {
        int headerEnd = rawResponse.indexOf("\r\n\r\n");
        if (headerEnd < 0) headerEnd = rawResponse.indexOf("\n\n");
        if (headerEnd < 0) return "";
        String headers = rawResponse.substring(0, headerEnd).toLowerCase(Locale.ROOT);
        int ctIdx = headers.indexOf("content-type:");
        if (ctIdx < 0) return "";
        int lineEnd = headers.indexOf('\n', ctIdx);
        return lineEnd < 0 ? headers.substring(ctIdx + 13) : headers.substring(ctIdx + 13, lineEnd);
    }

    private boolean isWafBlocked(Probe p) {
        if (!wafDetectionEnabled) return false;
        return wafDetector.detect(p.rawResponse, p.status, p.elapsed).isBlocked();
    }

    private Probe send(ApiEntry entry, String rawRequest) {
        try {
            long start = System.currentTimeMillis();
            HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequest(
                    ActiveProbeExecutor.resolveService(entry), rawRequest));
            long elapsed = System.currentTimeMillis() - start;
            int status = rr.response() != null ? rr.response().statusCode() : 0;
            String rawResp = rr.response() != null ? rr.response().toString() : "";
            return new Probe(rawRequest, rawResp, status, elapsed);
        } catch (Exception e) {
            if (logger != null) logger.warn("[XSS] 请求失败: %s", e.getMessage());
            return null;
        }
    }

    private static final class Probe {
        final String rawRequest;
        final String rawResponse;
        final int status;
        final long elapsed;
        Probe(String rawRequest, String rawResponse, int status, long elapsed) {
            this.rawRequest = rawRequest;
            this.rawResponse = rawResponse;
            this.status = status;
            this.elapsed = elapsed;
        }
    }
}
