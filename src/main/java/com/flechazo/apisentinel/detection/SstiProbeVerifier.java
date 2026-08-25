package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.HttpMessageUtils;

import java.util.List;

/** SSTI 模板注入验证器——7 引擎探针 + 控制请求防误报。 */
public class SstiProbeVerifier {

    public record TemplateProbe(String engine, String expression, String expected) {}

    private static final List<TemplateProbe> PROBES = List.of(
            new TemplateProbe("jinja2", "{{7*7}}", "49"),
            new TemplateProbe("jinja2-str", "{{7*'7'}}", "7777777"),
            new TemplateProbe("freemarker", "${7*7}", "49"),
            new TemplateProbe("erb", "<%= 7*7 %>", "49"),
            new TemplateProbe("smarty", "{7*7}", "49"),
            new TemplateProbe("velocity", "#set($x=7*7)${x}", "49"),
            new TemplateProbe("pebble", "{{3*3}}", "9")
    );

    public record SstiResult(
            boolean confirmed,
            String engine,
            String expression,
            String detail,
            boolean wafBlocked,
            String sentRequest,
            String receivedResponse,
            int statusCode,
            long elapsedMs
    ) {
        public static SstiResult notConfirmed(String detail) {
            return new SstiResult(false, null, null, detail, false, null, null, 0, 0);
        }
    }

    private final MontoyaApi api;
    private final LeveledLogger logger;
    private final WafDetector wafDetector;
    private final boolean wafDetectionEnabled;

    public SstiProbeVerifier(MontoyaApi api, LeveledLogger logger, boolean wafDetectionEnabled) {
        this.api = api;
        this.logger = logger;
        this.wafDetector = new WafDetector(logger);
        this.wafDetectionEnabled = wafDetectionEnabled;
    }

    public SstiResult verify(ApiEntry entry, String paramName,
                             String paramLocation, String paramValue,
                             String targetEngine) {
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty()) {
            return SstiResult.notConfirmed("无捕获请求，无法验证");
        }

        // First send a control request to check if expected output already exists
        String controlVal = "apsen_ssti_ctrl";
        String controlRaw = BlindParamMutator.mutate(raw, paramName, paramLocation, controlVal);
        String controlBody = "";
        if (controlRaw != null) {
            Probe ctrl = send(entry, controlRaw);
            if (ctrl != null) {
                controlBody = HttpMessageUtils.bodyOf(ctrl.rawResponse);
            }
        }

        List<TemplateProbe> probes = targetEngine == null || targetEngine.isBlank() || "auto".equalsIgnoreCase(targetEngine)
                ? PROBES
                : PROBES.stream().filter(p -> p.engine().startsWith(targetEngine.toLowerCase())).toList();

        int wafBlocked = 0;
        for (TemplateProbe tp : probes) {
            String mutated = BlindParamMutator.mutate(raw, paramName, paramLocation, tp.expression());
            if (mutated == null) {
                return SstiResult.notConfirmed("无法在 " + paramLocation + " 定位参数 " + paramName);
            }

            Probe probe = send(entry, mutated);
            if (probe == null) continue;

            if (isWafBlocked(probe)) {
                wafBlocked++;
                continue;
            }

            String body = HttpMessageUtils.bodyOf(probe.rawResponse);
            SstiVerdict verdict = classify(body, tp.expected(), controlBody);
            if (verdict == SstiVerdict.CONFIRMED) {
                String detail = "SSTI 确认: " + tp.expression() + " → 响应含 " + tp.expected()
                        + " (engine: " + tp.engine() + ")";
                if (logger != null) {
                    logger.info("[SSTI] %s 参数 %s %s", entry.getApiPath(), paramName, detail);
                }
                return new SstiResult(true, tp.engine(), tp.expression(), detail, false,
                        probe.rawRequest, probe.rawResponse, probe.status, probe.elapsed);
            }
        }

        if (wafBlocked > 0 && wafBlocked >= probes.size()) {
            return new SstiResult(false, null, null,
                    probes.size() + " 种模板表达式全被 WAF 拦截", true, null, null, 0, 0);
        }
        return SstiResult.notConfirmed("已测试 " + probes.size() + " 种模板引擎表达式，均未在响应中产生预期计算结果");
    }

    public enum SstiVerdict { CONFIRMED, NOT_VULNERABLE }

    public static SstiVerdict classify(String responseBody, String expectedOutput, String controlBody) {
        if (responseBody == null || !responseBody.contains(expectedOutput)) {
            return SstiVerdict.NOT_VULNERABLE;
        }
        // False-positive guard: if control response already contains the expected output
        if (controlBody != null && controlBody.contains(expectedOutput)) {
            return SstiVerdict.NOT_VULNERABLE;
        }
        return SstiVerdict.CONFIRMED;
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
            if (logger != null) logger.warn("[SSTI] 请求失败: %s", e.getMessage());
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
