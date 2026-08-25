package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.flechazo.apisentinel.auth.ResponseComparator;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.HttpMessageUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Business-logic flaw verifier: programmatic tests for the 6 classes in
 * business-logic.md (price tamper / step skip / negative value / coupon
 * reuse / concurrent race / batch enumeration). These are REAL business
 * operations — gated by config (default off) in Pipeline; the Agent tool is
 * available whenever the AI judges the target authorized.
 */
public class BusinessLogicVerifier {

    public enum TestType {
        TAMPER_PRICE, STEP_SKIP, NEGATIVE_VALUE,
        REPEAT_COUPON, CONCURRENT_RACE, BATCH_ENUMERATE;

        /** Parse from tool input ("tamper_price" etc.); null when unknown. */
        public static TestType fromInput(String s) {
            if (s == null) return null;
            return switch (s.toLowerCase().trim()) {
                case "tamper_price" -> TAMPER_PRICE;
                case "step_skip" -> STEP_SKIP;
                case "negative_value" -> NEGATIVE_VALUE;
                case "repeat_coupon" -> REPEAT_COUPON;
                case "concurrent_race" -> CONCURRENT_RACE;
                case "batch_enumeration", "batch_enumerate" -> BATCH_ENUMERATE;
                default -> null;
            };
        }
    }

    /** Verdict of one business-logic test. */
    public record LogicFlawResult(
            boolean confirmed,
            TestType testType,
            String detail,
            String sentRequest,     // decisive request ("" when nothing sent)
            String receivedResponse,
            int statusCode
    ) {
        static LogicFlawResult none(TestType t, String detail) {
            return new LogicFlawResult(false, t, detail, "", "", 0);
        }
    }

    private final MontoyaApi api;
    private final LeveledLogger logger;

    public BusinessLogicVerifier(MontoyaApi api, LeveledLogger logger) {
        this.api = api;
        this.logger = logger;
    }

    public LogicFlawResult verify(TestType type, ApiEntry entry, Params params) {
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty()) {
            return LogicFlawResult.none(type, "无捕获请求，无法验证");
        }
        return switch (type) {
            case TAMPER_PRICE -> valueProbe(type, entry, params.targetParam,
                    params.targetValue != null ? List.of(params.targetValue)
                            : List.of("0.01", "-100", "1e-10"),
                    "价格/金额被接受");
            case NEGATIVE_VALUE -> valueProbe(type, entry, params.targetParam,
                    params.targetValue != null ? List.of(params.targetValue)
                            : List.of("-1", "-100"),
                    "负数值被接受");
            case REPEAT_COUPON -> repeatCoupon(entry, params);
            case STEP_SKIP -> stepSkip(entry, params);
            case CONCURRENT_RACE -> concurrentRace(entry, params.count);
            case BATCH_ENUMERATE -> batchEnumerate(entry, params.targetParam);
        };
    }

    /** Tool input carrier. */
    public static final class Params {
        public String targetParam = "";
        public String targetValue;   // null = use per-type defaults
        public String targetStep;
        public int count = 5;
    }

    // ======================== Test implementations ========================

    /** Replace target param with probe values; 2xx acceptance = confirmed. */
    private LogicFlawResult valueProbe(TestType type, ApiEntry entry, String paramName,
                                       List<String> values, String flaw) {
        String raw = entry.getLastRawRequest();
        if (paramName == null || paramName.isEmpty()) {
            paramName = guessBusinessField(HttpMessageUtils.bodyOf(raw));
            if (paramName == null) return LogicFlawResult.none(type, "未指定 target_param 且请求体中未发现业务字段");
        }
        String location = BlindParamMutator.locateParam(entry, paramName);
        String original = originalValue(entry, paramName, location);
        for (String v : values) {
            String mutated = BlindParamMutator.mutate(raw, paramName, location, v);
            if (mutated == null) continue;
            Sent s = send(entry, mutated);
            if (s == null) continue;
            if (s.status >= 200 && s.status < 300) {
                return new LogicFlawResult(true, type,
                        paramName + "=" + v + " 被接受（响应 " + s.status + "，原值 " + original
                      + "）——" + flaw + "，请人工确认业务影响",
                        mutated, s.rawResponse, s.status);
            }
        }
        return LogicFlawResult.none(type, "所有探测值均被拒绝（4xx/5xx），校验有效");
    }

    /** Send the same coupon request twice; both accepted = confirmed. */
    private LogicFlawResult repeatCoupon(ApiEntry entry, Params params) {
        String raw = entry.getLastRawRequest();
        Sent first = send(entry, raw);
        if (first == null) return LogicFlawResult.none(TestType.REPEAT_COUPON, "首次请求失败");
        if (first.status < 200 || first.status >= 300) {
            return LogicFlawResult.none(TestType.REPEAT_COUPON,
                    "原始优惠券请求本身未成功（" + first.status + "），无法验证重复使用");
        }
        Sent second = send(entry, raw);
        if (second == null) return LogicFlawResult.none(TestType.REPEAT_COUPON, "第二次请求失败");
        if (second.status >= 200 && second.status < 300) {
            return new LogicFlawResult(true, TestType.REPEAT_COUPON,
                    "同一优惠券请求连续两次均返回 " + second.status + "——疑似可重复使用",
                    raw, second.rawResponse, second.status);
        }
        return LogicFlawResult.none(TestType.REPEAT_COUPON,
                "第二次使用被拒绝（" + second.status + "），防重放有效");
    }

    /** Jump directly to a later step; 2xx = flow bypassed. */
    private LogicFlawResult stepSkip(ApiEntry entry, Params params) {
        String raw = entry.getLastRawRequest();
        String target = HttpMessageUtils.requestTarget(raw);
        String path = target.contains("?") ? target.substring(0, target.indexOf('?')) : target;
        String query = target.contains("?") ? target.substring(target.indexOf('?')) : "";
        String step = params.targetStep != null && !params.targetStep.isEmpty()
                ? params.targetStep : "final";

        String newPath;
        if (path.toLowerCase().matches(".*step\\d+.*")) {
            newPath = path.replaceAll("(?i)step\\d+", step.startsWith("step") ? step : "step" + step.replaceAll("\\D", ""));
        } else {
            newPath = path + "/" + step;
        }
        String mutated = HttpMessageUtils.replaceRequestTarget(raw, newPath + query);
        Sent s = send(entry, mutated);
        if (s == null) return LogicFlawResult.none(TestType.STEP_SKIP, "跳步请求失败");
        if (s.status >= 200 && s.status < 300) {
            return new LogicFlawResult(true, TestType.STEP_SKIP,
                    "直接访问 " + newPath + " 返回 " + s.status + "——疑似绕过中间步骤",
                    mutated, s.rawResponse, s.status);
        }
        return LogicFlawResult.none(TestType.STEP_SKIP,
                "跳步访问被拒绝/重定向（" + s.status + "），流程控制有效");
    }

    /** Fire N identical requests concurrently; all succeed = suspected race
     *  (business-side confirmation of over-grant still required). */
    private LogicFlawResult concurrentRace(ApiEntry entry, int count) {
        int n = Math.max(2, Math.min(count, 10));
        String raw = entry.getLastRawRequest();
        ExecutorService pool = Executors.newFixedThreadPool(n);
        try {
            List<Future<Sent>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                futures.add(pool.submit(() -> send(entry, raw)));
            }
            int successes = 0;
            Sent last = null;
            for (Future<Sent> f : futures) {
                try {
                    Sent s = f.get(30, TimeUnit.SECONDS);
                    if (s != null) {
                        last = s;
                        if (s.status >= 200 && s.status < 300) successes++;
                    }
                } catch (Exception e) {
                    // count as failure
                }
            }
            if (successes >= n && last != null) {
                return new LogicFlawResult(true, TestType.CONCURRENT_RACE,
                        n + " 个并发请求全部成功（2xx）——疑似竞态窗口，请人工确认是否超额/重复",
                        raw, last.rawResponse, last.status);
            }
            return LogicFlawResult.none(TestType.CONCURRENT_RACE,
                    n + " 个并发请求中 " + successes + " 个成功，存在限流/幂等保护");
        } finally {
            pool.shutdownNow();
        }
    }

    /** Enumerate adjacent IDs; a 2xx response dissimilar to our own data =
     *  IDOR. */
    private LogicFlawResult batchEnumerate(ApiEntry entry, String paramName) {
        String raw = entry.getLastRawRequest();
        if (paramName == null || paramName.isEmpty()) paramName = "id";
        String location = BlindParamMutator.locateParam(entry, paramName);
        String original = originalValue(entry, paramName, location);
        long base;
        try {
            base = Long.parseLong(original.replaceAll("[^0-9]", ""));
        } catch (Exception e) {
            return LogicFlawResult.none(TestType.BATCH_ENUMERATE,
                    "参数 " + paramName + " 的值非数字（" + original + "），无法枚举");
        }

        HttpResponse baselineResponse = null;
        Sent baselineSent = send(entry, raw);
        if (baselineSent != null && baselineSent.response != null) {
            baselineResponse = baselineSent.response;
        }
        for (long id = base + 1; id <= base + 5; id++) {
            String mutated = BlindParamMutator.mutate(raw, paramName, location, String.valueOf(id));
            if (mutated == null) break;
            Sent s = send(entry, mutated);
            if (s == null || s.response == null) continue;
            if (s.status >= 200 && s.status < 300 && baselineResponse != null) {
                double sim = ResponseComparator.compare(baselineResponse, s.response);
                if (sim < 0.9) {
                    return new LogicFlawResult(true, TestType.BATCH_ENUMERATE,
                            paramName + "=" + id + " 返回 2xx 且与本人数据相似度仅 "
                          + String.format("%.0f%%", sim * 100) + "——疑似可枚举他人数据（IDOR）",
                            mutated, s.rawResponse, s.status);
                }
            }
        }
        return LogicFlawResult.none(TestType.BATCH_ENUMERATE,
                "相邻 5 个 ID 均未返回他人数据（拒绝或与本人数据一致）");
    }

    // ======================== helpers ========================

    private static final String[] BUSINESS_FIELD_HINTS = {
            "price", "total", "amount", "cost", "fee", "discount",
            "coupon", "promo", "voucher", "quantity", "qty", "num"
    };

    /** First JSON body key that looks business-sensitive. */
    public static String guessBusinessField(String body) {
        var obj = HttpMessageUtils.parseJsonObject(body);
        if (obj == null) return null;
        for (String key : obj.keySet()) {
            String k = key.toLowerCase();
            for (String hint : BUSINESS_FIELD_HINTS) {
                if (k.contains(hint)) return key;
            }
        }
        return null;
    }

    private static String originalValue(ApiEntry entry, String param, String location) {
        String raw = entry.getLastRawRequest();
        var params = HttpMessageUtils.parseQueryParams(HttpMessageUtils.requestTarget(raw));
        if (params.containsKey(param)) return params.get(param);
        var obj = HttpMessageUtils.parseJsonObject(HttpMessageUtils.bodyOf(raw));
        if (obj != null && obj.has(param) && obj.get(param).isJsonPrimitive()) {
            return obj.get(param).getAsString();
        }
        return "";
    }

    private static final class Sent {
        final HttpResponse response;
        final String rawResponse;
        final int status;

        Sent(HttpResponse response, String rawResponse, int status) {
            this.response = response;
            this.rawResponse = rawResponse;
            this.status = status;
        }
    }

    private Sent send(ApiEntry entry, String rawRequest) {
        try {
            HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequest(
                    ActiveProbeExecutor.resolveService(entry), rawRequest));
            int status = rr.response() != null ? rr.response().statusCode() : 0;
            String rawResp = rr.response() != null ? rr.response().toString() : "";
            return new Sent(rr.response(), rawResp, status);
        } catch (Exception e) {
            if (logger != null) logger.warn("[BusinessLogic] 请求失败: %s", e.getMessage());
            return null;
        }
    }
}
