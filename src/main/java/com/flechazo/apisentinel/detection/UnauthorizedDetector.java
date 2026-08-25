package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.handler.RateLimiter;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import com.flechazo.apisentinel.model.PassiveFinding;
import com.flechazo.apisentinel.model.VulnType;
import com.flechazo.apisentinel.repository.ApiRepository;
import com.flechazo.apisentinel.ui.UiEventBus;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.*;

/** 未授权访问检测器——去掉认证头重放请求，判断是否返回了受保护数据。 */
public class UnauthorizedDetector {

    private final MontoyaApi api;
    private final RateLimiter rateLimiter;
    private final LeveledLogger logger;
    private final UiEventBus uiEventBus;
    private final ApiRepository repository;
    private final ExecutorService detectionPool;
    private final Set<String> checkedPaths = ConcurrentHashMap.newKeySet();

    public UnauthorizedDetector(MontoyaApi api, RateLimiter rateLimiter,
                                LeveledLogger logger, UiEventBus uiEventBus,
                                ApiRepository repository) {
        this.api = api;
        this.rateLimiter = rateLimiter;
        this.logger = logger;
        this.uiEventBus = uiEventBus;
        this.repository = repository;
        this.detectionPool = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "api-sentinel-unauth-detector");
            t.setDaemon(true);
            return t;
        });
    }

    public void detect(HttpRequest originalRequest, ApiEntry matchedApi) {
        String method = originalRequest.method();
        // Skip non-business methods — OPTIONS (CORS preflight) / HEAD always
        // return 2xx and have no auth semantics; TRACE is a diagnostic method.
        String m = method != null ? method.toUpperCase() : "";
        if (m.equals("OPTIONS") || m.equals("HEAD") || m.equals("TRACE")) {
            return;
        }

        String path = matchedApi.getApiPath();
        // Dedup by method+path so an earlier OPTIONS doesn't block a later
        // GET/POST from being checked on the same endpoint.
        String dedupKey = m + " " + path;
        if (!checkedPaths.add(dedupKey)) {
            return;
        }

        if (!rateLimiter.tryAcquire()) {
            logger.debug("未授权检测被限流: %s %s", method, path);
            checkedPaths.remove(dedupKey);
            return;
        }

        // Detached copy built on the CALLER thread — Montoya request objects
        // must not be used from another thread after the handler returns, and
        // the lambda below runs on the detection pool. Fall back to the
        // original reference if copying fails (e.g. exotic HTTP/2 shapes).
        HttpRequest requestForAsync;
        try {
            requestForAsync = HttpRequest.httpRequest(
                    originalRequest.httpService(), originalRequest.toByteArray());
        } catch (Exception copyEx) {
            logger.debug("未授权检测: 请求拷贝失败，使用原始引用: %s", copyEx.getMessage());
            requestForAsync = originalRequest;
        }
        final HttpRequest detachedRequest = requestForAsync;

        detectionPool.submit(() -> {
            try {
                int originalStatusCode = matchedApi.getLastStatusCode();
                String originalBody = matchedApi.getLastRawResponse();

                // Strip all known auth headers (aligned with SendRequestTool's
                // AUTH_HEADER_NAMES) — if Cookie + Authorization both exist,
                // both are removed so the request is truly unauthenticated.
                HttpRequest stripped = detachedRequest
                        .withRemovedHeader("Cookie")
                        .withRemovedHeader("Authorization")
                        .withRemovedHeader("X-Auth-Token")
                        .withRemovedHeader("X-Access-Token")
                        .withRemovedHeader("X-API-Key")
                        .withRemovedHeader("X-Session-Id")
                        .withRemovedHeader("Token")
                        .withRemovedHeader("Session");

                // Also strip token-like query parameters (?token=/api_key=/access_token=)
                stripped = stripAuthQueryParams(stripped);

                HttpRequestResponse response = api.http().sendRequest(stripped);

                if (response.response() != null) {
                    int strippedStatus = response.response().statusCode();
                    // Any 2xx (not just 200) on the auth-stripped request means
                    // the protected resource is still served without auth.
                    if (strippedStatus >= 200 && strippedStatus < 300) {
                        String strippedBody = response.response().body() != null
                                ? response.response().body().toString() : "";

                        // High similarity to the authenticated baseline => the
                        // same data is returned without auth => unauthorized access.
                        // Jaccard shingling is robust to JSON key ordering / minor
                        // whitespace shifts that broke the old positional compare.
                        if (originalBody != null && !originalBody.isEmpty()
                                && !strippedBody.isEmpty() && bodySimilarity(originalBody, strippedBody) < 0.3) {
                            logger.debug("未授权检测: %s 响应差异过大，判定为非未授权", path);
                            return;
                        }

                        logger.info("疑似未授权访问（待人工确认）: %s", path);

                        // Note: this heuristic can't tell "endpoint doesn't
                        // require auth at all" (stripping a header that was
                        // never checked trivially still returns 2xx/same body)
                        // apart from "endpoint requires auth but doesn't
                        // enforce it" (a real finding) — a public GET with a
                        // browser-sent Cookie it never reads will always look
                        // identical to this check. So this only advances the
                        // human review workflow (PENDING_REVIEW), it does not
                        // unilaterally declare VULNERABLE — that call is left
                        // to manual confirmation (or a real AI/Pipeline/Agent
                        // analysis), consistent with 状态 being a human-driven
                        // triage field rather than an automated verdict.
                        String evidence = String.format(
                            "[未授权检测-待确认] 去除认证头后仍返回 2xx (%d)\n原始状态码: %d\n响应长度: %d 字节\n去除的头: Cookie, Authorization, X-Auth-Token\n检测时间: %s\n"
                          + "注意: 无法区分\"该接口本来就不需要认证\"和\"需要认证但未强制\"，请人工确认后再判定。",
                            strippedStatus,
                            originalStatusCode,
                            response.response().body().length(),
                            java.time.LocalDateTime.now().toString()
                        );

                        // Structured (source,title) dedup replaces the old
                        // note.contains("[越权]") guard: checkedPaths limits
                        // probes to one per method+path per running session
                        // but resets on restart — the fixed title dedups
                        // across restarts too (the old guard re-appended).
                        boolean added = matchedApi.addPassiveFindingIfAbsent(new PassiveFinding(
                                PassiveFinding.newId(), PassiveFinding.Source.UNAUTHORIZED,
                                "MEDIUM", "越权", "未授权访问探测（待确认）",
                                evidence, "", System.currentTimeMillis()));
                        if (added) {
                            repository.markDirty();
                        }

                        // Only advance to PENDING_REVIEW if the current status
                        // hasn't already been manually confirmed — don't
                        // clobber a human's "已通过/存在漏洞" decision with a
                        // low-confidence automated heuristic.
                        if (matchedApi.getStatus() == ApiStatus.UNTESTED
                                || matchedApi.getStatus() == ApiStatus.UNDER_TEST) {
                            matchedApi.updateStatus(ApiStatus.PENDING_REVIEW, VulnType.UNAUTHORIZED,
                                    VulnType.UNAUTHORIZED.getDisplayName());
                        }

                        // Deliberately NOT pushed to Burp's native Repeater
                        // (used to call api.repeater().sendToRepeater(stripped,
                        // "Unauth: " + path) here) — this heuristic has a real
                        // false-positive rate on public endpoints (see the
                        // comment above), so on a target with many public
                        // GETs it was auto-spawning a large number of "Unauth: "
                        // tabs in Repeater with no way to turn just that off.
                        // The finding is still fully recorded above (note +
                        // PENDING_REVIEW status) — filter the table by that
                        // status to review candidates, and send any one of
                        // them to Repeater manually (via 历史流量/内置 Repeater)
                        // if you want to poke at it further.
                        uiEventBus.postTableRefresh();
                    } else {
                        logger.debug("未授权检测: %s 返回 %d，非未授权", path, strippedStatus);
                    }
                } else {
                    logger.debug("未授权检测: %s 无响应", path);
                }
            } catch (Exception e) {
                logger.error("未授权检测异常: %s - %s", path, e.getMessage());
            }
        });
    }

    public void clearChecked() {
        checkedPaths.clear();
    }

    public void shutdown() {
        detectionPool.shutdownNow();
        try {
            detectionPool.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Body similarity via 3-gram Jaccard, robust to JSON key ordering / minor
     * whitespace shifts (the old positional char-by-char compare returned ~0
     * for semantically identical bodies with reordered keys — a false negative).
     */
    /** Strip token-like query/form parameters (?token=&api_key=&access_token=...). */
    private HttpRequest stripAuthQueryParams(HttpRequest req) {
        if (!req.hasParameters()) return req;
        List<ParsedHttpParameter> toRemove = new ArrayList<>();
        for (ParsedHttpParameter p : req.parameters()) {
            String name = p.name() == null ? "" : p.name().toLowerCase();
            if (isAuthParam(name)) toRemove.add(p);
        }
        if (toRemove.isEmpty()) return req;
        return req.withRemovedParameters(toRemove);
    }

    private static boolean isAuthParam(String name) {
        if (name == null || name.isEmpty()) return false;
        return name.contains("token") || name.contains("apikey")
                || name.equals("api_key") || name.contains("access_token")
                || name.contains("auth") || name.contains("session")
                || name.contains("secret") || name.equals("key")
                || name.equals("jwt");
    }

    private double bodySimilarity(String a, String b) {
        if (a == null || b == null) return 0.0;
        if (a.equals(b)) return 1.0;
        int maxLen = Math.max(a.length(), b.length());
        if (maxLen == 0) return 1.0;

        // Cap to bound memory; 8000 chars is plenty to distinguish authz outcomes.
        String sa = a.length() > 8000 ? a.substring(0, 8000) : a;
        String sb = b.length() > 8000 ? b.substring(0, 8000) : b;

        java.util.Set<String> setA = shingles(sa, 3);
        java.util.Set<String> setB = shingles(sb, 3);
        if (setA.isEmpty() && setB.isEmpty()) return 1.0;
        if (setA.isEmpty() || setB.isEmpty()) return 0.0;

        int intersection = 0;
        java.util.Set<String> smaller = setA.size() <= setB.size() ? setA : setB;
        java.util.Set<String> larger = smaller == setA ? setB : setA;
        for (String s : smaller) if (larger.contains(s)) intersection++;
        int union = setA.size() + setB.size() - intersection;
        return (double) intersection / union;
    }

    private static java.util.Set<String> shingles(String s, int n) {
        java.util.Set<String> out = new java.util.HashSet<>();
        if (s == null || s.length() < n) {
            if (s != null && !s.isEmpty()) out.add(s);
            return out;
        }
        for (int i = 0; i + n <= s.length(); i++) {
            out.add(s.substring(i, i + n));
        }
        return out;
    }
}
