package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.flechazo.apisentinel.ai.pipeline.PayloadResult;
import com.flechazo.apisentinel.auth.ResponseComparator;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.testgen.model.TestCase;
import com.flechazo.apisentinel.util.HttpMessageUtils;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Programmatic active probes that turn passive suspicions into verified
 * evidence: CORS origin-variant reflection, JWT alg:none forgery replay,
 * CRLF canary injection and NoSQL differential/timing tests.
 *
 * Probe logic distilled from bughunter's cors_scanner.py / jwt_scanner.py /
 * crlf_scanner.py / nosqli_scanner.py (shuvonsec/claude-bug-bounty, MIT
 * License — see docs/THIRD-PARTY.md). Only deterministic, low-volume checks
 * are ported; each probe fires only when its trigger condition matches and
 * every classification is a pure function (unit-testable, no network).
 *
 * Results are ordinary {@link PayloadResult}s with synthetic TestCases
 * (categories CORS探测/JWT伪造/CRLF探测/NoSQL探测), so they automatically
 * flow into the Repeater follow-up rows, persistence, the Stage 6 verdict
 * prompt and VerdictValidator matching — a probe whose programmatic check
 * confirms an issue carries anomalyDetected=true.
 */
public class ActiveProbeExecutor {

    /** Global cap on probe requests per analysis run. */
    private static final int MAX_PROBE_REQUESTS = 20;
    private static final long NOSQL_SLEEP_MS = 3000;

    private static final Pattern JWT_PATTERN =
            Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*");

    /** Top-level JSON keys that mark an auth-style endpoint (NoSQL trigger). */
    private static final String[] ID_KEYS = {"username", "user", "account", "email", "login", "mobile"};
    private static final String[] PASS_KEYS = {"password", "passwd", "pass", "pwd"};

    private final MontoyaApi api;
    private final LeveledLogger logger;
    private final WafDetector wafDetector;
    private final boolean wafDetectionEnabled;
    private int sent;

    public ActiveProbeExecutor(MontoyaApi api, LeveledLogger logger, boolean wafDetectionEnabled) {
        this.api = api;
        this.logger = logger;
        this.wafDetector = new WafDetector(logger);
        this.wafDetectionEnabled = wafDetectionEnabled;
    }

    /**
     * Run every probe whose trigger condition matches the entry's captured
     * traffic. Never throws — probe failures degrade to empty results.
     */
    public List<PayloadResult> execute(ApiEntry entry) {
        List<PayloadResult> out = new ArrayList<>();
        try {
            String rawReq = entry.getLastRawRequest();
            String rawResp = entry.getLastRawResponse();
            if (rawReq == null || rawReq.isEmpty()) return out;

            if (shouldProbeCors(rawResp)) {
                out.addAll(probeCors(entry, rawReq));
            }
            if (entry.getLastStatusCode() > 0 && entry.getLastStatusCode() < 400
                    && findJwtInRequest(rawReq) != null) {
                out.addAll(probeJwt(entry, rawReq, rawResp));
            }
            out.addAll(probeCrlf(entry, rawReq));
            if (isJsonAuthRequest(rawReq)) {
                out.addAll(probeNosql(entry, rawReq));
            }
            // Command injection probe — fires when the request has parameters
            // that look like file names, paths, or generic string inputs
            out.addAll(probeCommandInjection(entry, rawReq));
        } catch (Exception e) {
            if (logger != null) logger.warn("[ActiveProbe] 执行异常: %s", e.getMessage());
        }
        return out;
    }

    // ======================== CORS probe ========================

    /** Trigger: baseline already exposes an ACAO header, or the endpoint is a
     *  cookie-authenticated JSON API (cross-origin data theft surface). */
    public static boolean shouldProbeCors(String rawResponse) {
        if (rawResponse == null) return false;
        if (getHeader(rawResponse, "Access-Control-Allow-Origin") != null) return true;
        return getHeader(rawResponse, "Set-Cookie") != null
                && getHeader(rawResponse, "Content-Type") != null
                && getHeader(rawResponse, "Content-Type").toLowerCase().contains("application/json");
    }

    /** Pure CORS classification: exact ACAO reflection of the sent origin. */
    public static String classifyCors(String sentOrigin, String rawResponse) {
        String acao = getHeader(rawResponse, "Access-Control-Allow-Origin");
        if (acao == null) return "NONE";
        acao = acao.trim();
        boolean acac = "true".equalsIgnoreCase(
                trimToEmpty(getHeader(rawResponse, "Access-Control-Allow-Credentials")).trim());
        if ("*".equals(acao)) {
            // Wildcard+credentials is invalid per spec (browser ignores it) and
            // wildcard-alone is informational — never a confirmed finding here
            // (consistent with SafetyRules' CORS treatment).
            return acac ? "MEDIUM" : "NONE";
        }
        if (acao.equalsIgnoreCase(sentOrigin.trim())) {
            return acac ? "HIGH" : "MEDIUM";
        }
        return "NONE";
    }

    private List<PayloadResult> probeCors(ApiEntry entry, String rawReq) {
        String host = HttpMessageUtils.hostOnly(entry.getDomain());
        String[] origins = {
                "https://evil.example",
                "null",
                "https://" + host + ".evil.example",
                "https://evil" + host,
                "https://attacker." + host,
                "http://" + host
        };
        List<PayloadResult> out = new ArrayList<>();
        for (String origin : origins) {
            if (sent >= MAX_PROBE_REQUESTS) break;
            String raw = replaceOrInsertHeader(rawReq, "Origin", origin);
            ProbeResponse pr = send(entry, raw);
            if (pr == null) continue;
            String verdict = classifyCors(origin, pr.rawResponse);
            boolean anomaly = "HIGH".equals(verdict) || "MEDIUM".equals(verdict);
            String name = "CORS探测-Origin变体 " + origin
                    + (anomaly ? " → " + ("HIGH".equals(verdict) ? "反射+凭证" : "反射无凭证") : "");
            out.add(result(name, "CORS探测", "Origin: " + origin, pr, anomaly,
                    "HIGH".equals(verdict) ? "HIGH" : "MEDIUM"));
            if (logger != null) logger.info("[ActiveProbe] CORS Origin=%s → %s (%d)",
                    origin, verdict, pr.status);
            sleep200();
        }
        return out;
    }

    // ======================== JWT alg:none probe ========================

    /** Forge an alg:none variant of a JWT: new minimal header, original
     *  payload, empty signature. Returns null on malformed input. */
    public static String forgeAlgNoneToken(String jwt, String algVariant) {
        if (jwt == null) return null;
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) return null;
        String headerJson = "{\"alg\":\"" + algVariant + "\",\"typ\":\"JWT\"}";
        String headerB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        return headerB64 + "." + parts[1] + ".";
    }

    private List<PayloadResult> probeJwt(ApiEntry entry, String rawReq, String rawResp) {
        String jwt = findJwtInRequest(rawReq);
        List<PayloadResult> out = new ArrayList<>();
        if (jwt == null) return out;
        HttpResponse baseline = safeParseResponse(rawResp);
        int baselineStatus = entry.getLastStatusCode();

        for (String alg : new String[]{"none", "None"}) {
            if (sent >= MAX_PROBE_REQUESTS) break;
            String forged = forgeAlgNoneToken(jwt, alg);
            if (forged == null) continue;
            String raw = rawReq.replace(jwt, forged);
            ProbeResponse pr = send(entry, raw);
            if (pr == null) continue;
            boolean accepted = false;
            if (pr.status == baselineStatus && baseline != null && pr.response != null) {
                accepted = ResponseComparator.compare(baseline, pr.response) >= 0.6;
            }
            String name = "JWT伪造-alg:" + alg + (accepted ? " → 服务端接受无签名token" : " → 被拒绝");
            out.add(result(name, "JWT伪造", "alg=" + alg, pr, accepted, "HIGH"));
            if (logger != null) logger.info("[ActiveProbe] JWT alg:%s → %s (%d)",
                    alg, accepted ? "ACCEPTED" : "rejected", pr.status);
            sleep200();
        }
        return out;
    }

    // ======================== CRLF probe ========================

    /** Pure check: canary cookie injected via response headers. */
    public static boolean detectCrlfCanary(String rawResponse) {
        if (rawResponse == null) return false;
        String headers = headerSection(rawResponse).toLowerCase(Locale.ROOT);
        int idx = 0;
        while ((idx = headers.indexOf("set-cookie:", idx)) >= 0) {
            int eol = headers.indexOf('\n', idx);
            String line = eol < 0 ? headers.substring(idx) : headers.substring(idx, eol);
            if (line.contains("crlftest=1")) return true;
            idx = eol < 0 ? headers.length() : eol + 1;
        }
        return false;
    }

    private List<PayloadResult> probeCrlf(ApiEntry entry, String rawReq) {
        String target = requestTarget(rawReq);
        String path = target.contains("?") ? target.substring(0, target.indexOf('?')) : target;
        String query = target.contains("?") ? target.substring(target.indexOf('?')) : "";
        String[] encodings = {"%0d%0a", "%0a", "%250d%250a", "%E5%98%8A%E5%98%8D"};
        String canary = "Set-Cookie:%20crlftest=1";

        List<PayloadResult> out = new ArrayList<>();
        for (String enc : encodings) {
            if (sent >= MAX_PROBE_REQUESTS) break;
            String injected = path + enc + canary + query;
            String raw = replaceRequestTarget(rawReq, injected);
            ProbeResponse pr = send(entry, raw);
            if (pr == null) continue;
            boolean hit = detectCrlfCanary(pr.rawResponse);
            String name = "CRLF探测-" + enc + (hit ? " → 注入Set-Cookie成功" : "");
            out.add(result(name, "CRLF探测", path + enc + canary, pr, hit, "HIGH"));
            if (logger != null) logger.info("[ActiveProbe] CRLF %s → %s (%d)",
                    enc, hit ? "INJECTED" : "clean", pr.status);
            sleep200();
        }
        return out;
    }

    // ======================== NoSQL probe ========================

    /** Trigger: JSON body carrying auth-style fields (username/password…). */
    public static boolean isJsonAuthRequest(String rawRequest) {
        String ct = getHeader(rawRequest, "Content-Type");
        if (ct == null || !ct.toLowerCase().contains("application/json")) return false;
        JsonObject obj = parseJsonObject(bodyOf(rawRequest));
        if (obj == null) return false;
        return findKey(obj, ID_KEYS) != null;
    }

    /** Pure differential classification (baseline vs operator-variant). */
    public static String classifyNosql(int baselineStatus, int baselineBodyLen,
                                       int variantStatus, int variantBodyLen) {
        boolean baselineRejected = baselineStatus == 400 || baselineStatus == 401 || baselineStatus == 403;
        boolean variantPassed = variantStatus == 200 || variantStatus == 301 || variantStatus == 302;
        if (baselineRejected && variantPassed) return "BYPASS";
        if (baselineStatus == variantStatus && baselineBodyLen > 0) {
            long delta = (long) variantBodyLen - baselineBodyLen;
            long threshold = Math.max(64, baselineBodyLen / 4);
            if (delta > threshold) return "SUSPICIOUS";
        }
        return "NONE";
    }

    /** Pure timing confirmation (delay >= 70% of the requested sleep). */
    public static boolean confirmNosqlTiming(long elapsedMs, long sleepMs) {
        return elapsedMs >= sleepMs * 0.7;
    }

    private List<PayloadResult> probeNosql(ApiEntry entry, String rawReq) {
        List<PayloadResult> out = new ArrayList<>();
        JsonObject orig = parseJsonObject(bodyOf(rawReq));
        if (orig == null) return out;
        String idKey = findKey(orig, ID_KEYS);
        String passKey = findKey(orig, PASS_KEYS);
        if (idKey == null) return out;

        // Baseline: impossible credentials — expected to be rejected.
        JsonObject base = orig.deepCopy();
        base.addProperty(idKey, "nouser_probe_invalid");
        if (passKey != null) base.addProperty(passKey, "wrong_probe_pass");
        ProbeResponse basePr = send(entry, replaceBody(rawReq, base.toString()));
        if (basePr == null) return out;
        int bStatus = basePr.status;
        int bLen = basePr.bodyLength;
        if (logger != null) logger.info("[ActiveProbe] NoSQL 基线(不可能凭证) → %d (len=%d)", bStatus, bLen);
        boolean baselineRejected = bStatus == 400 || bStatus == 401 || bStatus == 403;

        // Operator variants on the id field (+ password when present).
        List<Object[]> variants = new ArrayList<>();
        JsonObject v1 = orig.deepCopy();
        JsonObject ne = new JsonObject();
        ne.add("$ne", null);
        v1.add(idKey, ne);
        if (passKey != null) v1.add(passKey, ne.deepCopy());
        variants.add(new Object[]{"{\"$ne\":null}", v1});

        JsonObject v2 = orig.deepCopy();
        JsonObject gt = new JsonObject();
        gt.addProperty("$gt", "");
        v2.add(idKey, gt);
        variants.add(new Object[]{"{\"$gt\":\"\"}", v2});

        JsonObject v3 = orig.deepCopy();
        JsonObject rx = new JsonObject();
        rx.addProperty("$regex", ".*");
        v3.add(idKey, rx);
        variants.add(new Object[]{"{\"$regex\":\".*\"}", v3});

        for (Object[] v : variants) {
            if (sent >= MAX_PROBE_REQUESTS) break;
            ProbeResponse pr = send(entry, replaceBody(rawReq, ((JsonObject) v[1]).toString()));
            if (pr == null) continue;
            String verdict = classifyNosql(bStatus, bLen, pr.status, pr.bodyLength);
            boolean anomaly = "BYPASS".equals(verdict);
            String name = "NoSQL探测-" + v[0] + ("BYPASS".equals(verdict) ? " → 认证绕过"
                    : "SUSPICIOUS".equals(verdict) ? " → 响应差异可疑" : "");
            out.add(result(name, "NoSQL探测", idKey + "=" + v[0], pr, anomaly,
                    anomaly ? "HIGH" : "MEDIUM"));
            if (logger != null) logger.info("[ActiveProbe] NoSQL %s → %s (%d, len=%d)",
                    v[0], verdict, pr.status, pr.bodyLength);
            sleep200();
        }

        // Timing confirmation via top-level $where sleep (only meaningful
        // when the endpoint actually rejected the impossible credentials).
        if (baselineRejected && sent < MAX_PROBE_REQUESTS) {
            JsonObject tw = orig.deepCopy();
            tw.addProperty("$where", "sleep(" + NOSQL_SLEEP_MS + ")");
            ProbeResponse pr = send(entry, replaceBody(rawReq, tw.toString()));
            if (pr != null) {
                boolean confirmed = confirmNosqlTiming(pr.elapsed, NOSQL_SLEEP_MS);
                String name = "NoSQL探测-$where时序" + (confirmed ? " → 延迟确认服务端JS执行" : "");
                out.add(result(name, "NoSQL探测", "$where=sleep(" + NOSQL_SLEEP_MS + ")",
                        pr, confirmed, "HIGH"));
                if (logger != null) logger.info("[ActiveProbe] NoSQL $where sleep → %dms (%s)",
                        pr.elapsed, confirmed ? "CONFIRMED" : "no delay");
            }
        }
        return out;
    }

    // ======================== Shared plumbing ========================

    /** One probe request/response with WAF fingerprinting applied. */
    private static class ProbeResponse {
        final String rawResponse;
        final HttpResponse response;
        final int status;
        final int bodyLength;
        final long elapsed;
        final String wafVendor;
        final int wafScore;

        ProbeResponse(String rawResponse, HttpResponse response, int status, int bodyLength,
                      long elapsed, String wafVendor, int wafScore) {
            this.rawResponse = rawResponse;
            this.response = response;
            this.status = status;
            this.bodyLength = bodyLength;
            this.elapsed = elapsed;
            this.wafVendor = wafVendor;
            this.wafScore = wafScore;
        }
    }

    private ProbeResponse send(ApiEntry entry, String rawRequest) {
        try {
            long start = System.currentTimeMillis();
            HttpRequestResponse rr = api.http().sendRequest(
                    HttpRequest.httpRequest(resolveService(entry), rawRequest));
            long elapsed = System.currentTimeMillis() - start;
            sent++;
            int status = rr.response() != null ? rr.response().statusCode() : 0;
            String rawResp = rr.response() != null ? rr.response().toString() : "";
            int bodyLen = rr.response() != null ? rr.response().bodyToString().length() : 0;
            WafDetector.WafDetectionResult waf = wafDetectionEnabled
                    ? wafDetector.detect(rawResp, status, elapsed)
                    : new WafDetector.WafDetectionResult(null, 0, "waf detection disabled");
            return new ProbeResponse(rawResp, rr.response(), status, bodyLen, elapsed,
                    waf.vendor(), waf.score());
        } catch (Exception e) {
            if (logger != null) logger.warn("[ActiveProbe] 请求失败: %s", e.getMessage());
            return null;
        }
    }

    private PayloadResult result(String name, String category, String payload,
                                 ProbeResponse pr, boolean anomaly, String risk) {
        TestCase tc = new TestCase(name, category, "", payload, "", "", null, "",
                "程序化主动探针（蒸馏自 bughunter 扫描器）",
                anomaly ? "程序化判定已确认" : "未见异常", risk);
        return new PayloadResult(tc, "", pr.rawResponse, pr.status, pr.elapsed, anomaly,
                System.currentTimeMillis(), -1, pr.wafVendor, pr.wafScore);
    }

    private void sleep200() {
        try {
            Thread.sleep(200);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    // ======================== Raw-message helpers ========================

    /** First JWT found in the request header section (Authorization/Cookie). */
    public static String findJwtInRequest(String rawRequest) {
        if (rawRequest == null) return null;
        Matcher m = JWT_PATTERN.matcher(headerSection(rawRequest));
        return m.find() ? m.group() : null;
    }

    // Raw-message helpers delegate to the shared util (single implementation
    // for all programmatic verifiers).
    private static String headerSection(String raw) {
        return HttpMessageUtils.headerSection(raw);
    }

    private static String bodyOf(String raw) {
        return HttpMessageUtils.bodyOf(raw);
    }

    /** Case-insensitive header lookup on a raw HTTP message. */
    public static String getHeader(String raw, String name) {
        return HttpMessageUtils.getHeader(raw, name);
    }

    private static String trimToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String replaceOrInsertHeader(String raw, String name, String value) {
        return HttpMessageUtils.replaceOrInsertHeader(raw, name, value);
    }

    private static String requestTarget(String raw) {
        return HttpMessageUtils.requestTarget(raw);
    }

    private static String replaceRequestTarget(String raw, String newTarget) {
        return HttpMessageUtils.replaceRequestTarget(raw, newTarget);
    }

    private static String replaceBody(String raw, String newBody) {
        return HttpMessageUtils.replaceBody(raw, newBody);
    }

    /** Resolve scheme/port/host for an entry (shared with other verifiers). */
    public static HttpService resolveService(ApiEntry entry) {
        String host = HttpMessageUtils.hostOnly(entry.getDomain());
        String lastUrl = entry.getLastUrl();
        boolean useHttps = lastUrl == null || !lastUrl.toLowerCase().startsWith("http://");
        int port = useHttps ? 443 : 80;
        if (entry.getDomain() != null && entry.getDomain().contains(":")) {
            try {
                port = Integer.parseInt(entry.getDomain().split(":")[1]);
            } catch (NumberFormatException ignored) {}
        }
        return HttpService.httpService(host, port, useHttps);
    }

    private static JsonObject parseJsonObject(String body) {
        return HttpMessageUtils.parseJsonObject(body);
    }

    /** First top-level key whose lower-cased name contains any candidate. */
    private static String findKey(JsonObject obj, String[] candidates) {
        for (Map.Entry<String, JsonElement> e : obj.entrySet()) {
            String k = e.getKey().toLowerCase(Locale.ROOT);
            for (String c : candidates) {
                if (k.contains(c)) return e.getKey();
            }
        }
        return null;
    }

    private static HttpResponse safeParseResponse(String raw) {
        try {
            return raw == null || raw.isEmpty() ? null : HttpResponse.httpResponse(raw);
        } catch (Exception e) {
            return null;
        }
    }

    // ======================== Command Injection probe ========================

    /** Command injection canaries: inject shell metacharacters + a marker
     *  command (echo/mark), check if the marker appears in the response body.
     *  Also includes a timing-based fallback (sleep) for blind injection. */
    private List<PayloadResult> probeCommandInjection(ApiEntry entry, String rawReq) {
        List<PayloadResult> results = new ArrayList<>();
        String host = HttpMessageUtils.hostOnly(entry.getDomain());
        String domain = entry.getDomain();
        int port = 80;
        boolean useHttps = domain != null && domain.startsWith("https");
        if (domain != null && domain.contains(":")) {
            try { port = Integer.parseInt(domain.split(":")[1]); } catch (Exception ignored) {}
        } else {
            port = useHttps ? 443 : 80;
        }
        HttpService service = HttpService.httpService(host, port, useHttps);

        // Find injectable parameters in query string or JSON body
        List<InjectableParam> params = extractInjectableParams(rawReq);
        if (params.isEmpty()) {
            params.add(new InjectableParam("default", "test", "query"));
        }

        // Unique marker to detect command execution
        String marker = "ASENTINEL" + System.currentTimeMillis();
        // Response-based canaries: ;echo MARKER  and  |echo MARKER
        String[] canaries = {
                ";echo " + marker,
                "|echo " + marker,
                "&&echo " + marker,
                "$(echo " + marker + ")",
                "`echo " + marker + "`"
        };

        int sent = 0;
        for (InjectableParam param : params) {
            if (sent >= MAX_PROBE_REQUESTS) break;
            for (String canary : canaries) {
                if (sent >= MAX_PROBE_REQUESTS) break;
                String modifiedReq = injectParam(rawReq, param, canary);
                if (modifiedReq == null) continue;
                try {
                    HttpRequest httpReq = HttpRequest.httpRequest(service, HttpMessageUtils.addProbeMarker(modifiedReq));
                    HttpRequestResponse resp = api.http().sendRequest(httpReq);
                    long start = System.currentTimeMillis();
                    long elapsed = System.currentTimeMillis() - start;
                    int code = resp.response() != null ? resp.response().statusCode() : 0;
                    String body = resp.response() != null ? resp.response().bodyToString() : "";
                    boolean hit = body.contains(marker);
                    results.add(new PayloadResult(
                            new TestCase("cmd_inj_" + param.name, "COMMAND_INJECTION", param.name, canary, "", "", null, "", "Shell metacharacter injection", "", "MEDIUM"),
                            HttpMessageUtils.buildRawRequest(resp.request()),
                            HttpMessageUtils.buildRawResponse(resp.response()),
                            code, elapsed, hit, start, -1, null, 0));
                    sent++;
                    if (hit) {
                        if (logger != null) logger.info("[ActiveProbe] 命令注入确认: %s=%s → 响应含 marker", param.name, canary);
                        return results;  // Confirmed — no need to try more
                    }
                } catch (Exception e) {
                    if (logger != null) logger.debug("[ActiveProbe] 命令注入探测失败: %s", e.getMessage());
                }
            }
        }

        // Timing-based fallback: inject ;sleep 3 and check if response is delayed
        if (sent < MAX_PROBE_REQUESTS && !results.isEmpty()) {
            long baseline = results.stream()
                    .filter(r -> !r.anomalyDetected())
                    .mapToLong(PayloadResult::responseTimeMs)
                    .min().orElse(500);
            if (baseline < 2000) {  // Only if baseline is reasonable
                for (InjectableParam param : params) {
                    if (sent >= MAX_PROBE_REQUESTS) break;
                    String modifiedReq = injectParam(rawReq, param, ";sleep 3");
                    if (modifiedReq == null) continue;
                    try {
                        long start = System.currentTimeMillis();
                        HttpRequest httpReq = HttpRequest.httpRequest(service, HttpMessageUtils.addProbeMarker(modifiedReq));
                        HttpRequestResponse resp = api.http().sendRequest(httpReq);
                        long elapsed = System.currentTimeMillis() - start;
                        boolean timing = elapsed > baseline + 2500;
                        results.add(new PayloadResult(
                                new TestCase("cmd_inj_timing_" + param.name, "COMMAND_INJECTION", param.name, ";sleep 3", "", "", null, "", "Timing-based command injection", "", "MEDIUM"),
                                HttpMessageUtils.buildRawRequest(resp.request()),
                                HttpMessageUtils.buildRawResponse(resp.response()),
                                resp.response() != null ? resp.response().statusCode() : 0,
                                elapsed, timing, start, -1, null, 0));
                        sent++;
                        if (timing && logger != null) {
                            logger.info("[ActiveProbe] 命令注入时序确认: %s → %dms (baseline %dms)", param.name, elapsed, baseline);
                        }
                    } catch (Exception e) {
                        if (logger != null) logger.debug("[ActiveProbe] 时序探测失败: %s", e.getMessage());
                    }
                    break;  // Only one timing probe needed
                }
            }
        }

        return results;
    }

    /** Simple injectable parameter representation. */
    private record InjectableParam(String name, String originalValue, String location) {}

    /** Extract injectable parameters from query string and JSON body. */
    private List<InjectableParam> extractInjectableParams(String rawReq) {
        List<InjectableParam> params = new ArrayList<>();
        // Parse query string from the request line
        String[] lines = rawReq.split("\r?\n");
        if (lines.length == 0) return params;
        String reqLine = lines[0];
        int q = reqLine.indexOf('?');
        if (q > 0) {
            String query = reqLine.substring(q + 1);
            int sp = query.indexOf(' ');
            if (sp > 0) query = query.substring(0, sp);
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    params.add(new InjectableParam(
                            pair.substring(0, eq),
                            pair.substring(eq + 1),
                            "query"));
                }
            }
        }
        // Parse JSON body for string fields
        String body = "";
        for (String line : lines) {
            if (line.isBlank() && body.isEmpty()) continue;
            if (!body.isEmpty()) body += "\n" + line;
        }
        // Simpler: find the double-newline separator
        int sep = rawReq.indexOf("\r\n\r\n");
        if (sep > 0) {
            body = rawReq.substring(sep + 4);
            if (body.startsWith("{")) {
                try {
                    JsonObject json = JsonParser.parseString(body).getAsJsonObject();
                    for (Map.Entry<String, JsonElement> e : json.entrySet()) {
                        if (e.getValue().isJsonPrimitive() && e.getValue().getAsString().length() < 200) {
                            params.add(new InjectableParam(e.getKey(), e.getValue().getAsString(), "json"));
                        }
                    }
                } catch (Exception ignored) {}
            }
        }
        return params;
    }

    /** Replace a parameter's value with the injected payload. */
    private String injectParam(String rawReq, InjectableParam param, String payload) {
        if ("query".equals(param.location)) {
            return rawReq.replace(param.name + "=" + param.originalValue,
                    param.name + "=" + payload);
        } else if ("json".equals(param.location)) {
            // Replace "key":"value" with "key":"payload"
            String oldVal = "\"" + param.name + "\":\"" + param.originalValue + "\"";
            String newVal = "\"" + param.name + "\":\"" + payload + "\"";
            return rawReq.replace(oldVal, newVal);
        }
        return null;
    }
}
