package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import java.util.List;

/**
 * Boolean-based blind SQL injection verifier: sends a true-condition and a
 * false-condition payload for the same parameter and compares the responses.
 * Programmatic verdict (no LLM): status-code difference, or body-length
 * difference &gt; 5%, confirms injection. WAF-blocked probes abort without
 * a verdict.
 *
 * Distilled decision logic follows bughunter's blind-SQLi methodology
 * (MIT — see docs/THIRD-PARTY.md); requests are built from the entry's
 * captured raw request via {@link BlindParamMutator}.
 */
public class BooleanBlindVerifier {

    /** Body-length difference ratio that counts as a true/false divergence. */
    public static final double LENGTH_DIFF_THRESHOLD = 0.05;
    /** Responses above this size are only compared by status + first 10KB. */
    private static final int MAX_COMPARE_BYTES = 10 * 1024;
    /** Max payload pairs to try before giving up. */
    private static final int MAX_ATTEMPTS = 3;

    public record PayloadPair(String trueSuffix, String falseSuffix, String technique) {}

    private static final List<PayloadPair> PAYLOAD_PAIRS = List.of(
            new PayloadPair(" AND 1=1", " AND 1=2", "basic"),
            new PayloadPair(" AND 1=1--", " AND 1=2--", "comment-terminate"),
            new PayloadPair("' AND '1'='1", "' AND '1'='2", "string-context"),
            new PayloadPair(") AND (1=1", ") AND (1=2", "paren-close"),
            new PayloadPair(" AND/**/ 1=1", " AND/**/ 1=2", "inline-comment"),
            new PayloadPair(" OR 1=1--", " OR 1=2--", "or-based"),
            new PayloadPair(" AND 1 LIKE 1", " AND 1 LIKE 2", "like-operator"),
            new PayloadPair(" AnD 1=1", " AnD 1=2", "case-mix"),
            new PayloadPair("%26%26 1=1", "%26%26 1=2", "url-encoded-and"),
            new PayloadPair(" AND MOD(2,1)=1", " AND MOD(2,1)=0", "math-function")
    );

    private final MontoyaApi api;
    private final LeveledLogger logger;
    private final WafDetector wafDetector;
    private final boolean wafDetectionEnabled;

    public BooleanBlindVerifier(MontoyaApi api, LeveledLogger logger, boolean wafDetectionEnabled) {
        this.api = api;
        this.logger = logger;
        this.wafDetector = new WafDetector(logger);
        this.wafDetectionEnabled = wafDetectionEnabled;
    }

    /**
     * Verify boolean blind SQLi on one parameter.
     * Iterates over multiple payload variants; WAF-blocked pairs are skipped automatically.
     */
    public BlindVerificationResult verify(ApiEntry entry, String paramName,
                                          String paramLocation, String paramValue) {
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty()) {
            return BlindVerificationResult.notConfirmed("boolean_blind", "无捕获请求，无法验证");
        }
        String base = paramValue == null ? "" : paramValue;

        int attempted = 0;
        int wafBlocked = 0;
        Probe lastTrueProbe = null;

        for (PayloadPair pair : PAYLOAD_PAIRS) {
            if (attempted >= MAX_ATTEMPTS) break;

            String trueRaw = BlindParamMutator.mutate(raw, paramName, paramLocation, base + pair.trueSuffix());
            String falseRaw = BlindParamMutator.mutate(raw, paramName, paramLocation, base + pair.falseSuffix());
            if (trueRaw == null || falseRaw == null) {
                if (attempted == 0) {
                    return BlindVerificationResult.notConfirmed("boolean_blind",
                            "无法在 " + paramLocation + " 定位参数 " + paramName);
                }
                continue;
            }

            attempted++;
            Probe trueProbe = send(entry, trueRaw);
            if (trueProbe == null) continue;
            lastTrueProbe = trueProbe;

            if (isWafBlocked(trueProbe)) {
                wafBlocked++;
                continue;
            }

            Probe falseProbe = send(entry, falseRaw);
            if (falseProbe == null) continue;

            if (isWafBlocked(falseProbe)) {
                wafBlocked++;
                continue;
            }

            String verdictDetail = classify(trueProbe, falseProbe);
            if (verdictDetail != null) {
                // [payload: ...] carries the FULL true/false payload texts —
                // callers put this detail into PayloadResult.testCase().payload(),
                // and VerdictValidator matches the LLM's cited payloadUsed
                // against that text. Without it the detail is a pure length
                // description and the LLM's natural citation (the FALSE half,
                // e.g. "1 AND 1=2" — the decisive side of the divergence)
                // matches nothing, so every programmatic blind-SQLi
                // confirmation gets demoted to suspected.
                String detail = verdictDetail + " [technique: " + pair.technique() + "]"
                        + " [payload: " + base + pair.trueSuffix() + " / "
                        + base + pair.falseSuffix() + "]";
                if (logger != null) {
                    logger.info("[BooleanBlind] %s 参数 %s 确认布尔盲注: %s",
                            entry.getApiPath(), paramName, detail);
                }
                return new BlindVerificationResult(true, "boolean_blind", detail,
                        false, pair.technique(),
                        trueProbe.rawRequest, trueProbe.rawResponse, trueProbe.status, trueProbe.elapsed);
            }
        }

        if (wafBlocked > 0 && wafBlocked >= attempted && lastTrueProbe != null) {
            return new BlindVerificationResult(false, "boolean_blind",
                    attempted + " 种 payload 全被 WAF 拦截，无法判定", true, "auto",
                    lastTrueProbe.rawRequest, lastTrueProbe.rawResponse,
                    lastTrueProbe.status, lastTrueProbe.elapsed);
        }
        return BlindVerificationResult.notConfirmed("boolean_blind",
                "已尝试 " + attempted + " 种 payload 变体，true/false 条件响应无差异");
    }

    /** Pure classifier: returns a confirmation detail, or null when no
     *  significant difference between the two probes. */
    public static String classify(int trueStatus, int trueLen, int falseStatus, int falseLen) {
        if (trueStatus != falseStatus) {
            return "状态码差异: true 条件 " + trueStatus + " vs false 条件 " + falseStatus;
        }
        int base = Math.max(trueLen, falseLen);
        if (base > 0) {
            double diff = Math.abs(trueLen - falseLen) / (double) base;
            if (diff > LENGTH_DIFF_THRESHOLD) {
                return "响应长度差异 " + Math.abs(trueLen - falseLen) + " 字节 ("
                        + String.format("%.1f%%", diff * 100) + "): true " + trueLen
                        + " vs false " + falseLen;
            }
        }
        return null;
    }

    private String classify(Probe t, Probe f) {
        return classify(t.status, t.bodyLength(), f.status, f.bodyLength());
    }

    private boolean isWafBlocked(Probe p) {
        if (!wafDetectionEnabled) return false;
        return wafDetector.detect(p.rawResponse, p.status, p.elapsed).isBlocked();
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

        int bodyLength() {
            String body = com.flechazo.apisentinel.util.HttpMessageUtils.bodyOf(rawResponse);
            return Math.min(body.length(), MAX_COMPARE_BYTES);
        }
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
            if (logger != null) logger.warn("[BooleanBlind] 请求失败: %s", e.getMessage());
            return null;
        }
    }
}
