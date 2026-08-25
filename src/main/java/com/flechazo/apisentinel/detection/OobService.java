package com.flechazo.apisentinel.detection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import com.flechazo.apisentinel.config.AppConfig;
import com.flechazo.apisentinel.logging.LeveledLogger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.Consumer;

/** OOB 回连服务——管理 Collaborator 探针生成与自动轮询，关联盲注/SSRF 回连。 */
public class OobService {

    private static final long PROBE_TTL_MS = 60 * 60 * 1000; // 1 hour

    private final MontoyaApi api;
    private final AppConfig config;
    private final LeveledLogger logger;
    private final HttpClient httpClient;

    private volatile CollaboratorClient collaboratorClient;
    private final ConcurrentHashMap<String, OobProbeRecord> probeMap = new ConcurrentHashMap<>();
    private final Set<String> seenInteractionIds = ConcurrentHashMap.newKeySet();
    private volatile ScheduledExecutorService scheduler;
    private volatile Consumer<List<OobInteractionHit>> interactionCallback;

    public OobService(MontoyaApi api, AppConfig config, LeveledLogger logger) {
        this.api = api;
        this.config = config;
        this.logger = logger;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public boolean isEnabled() { return config.isOobUsable(); }

    // ─── Records ───

    public record OobProbeRecord(String payloadId, String fullHostname,
                                  String entryId, String entryPath,
                                  String parameter, String vulnType, long generatedAt) {}

    public record OobInteractionHit(OobProbeRecord probe, String interactionType, long detectedAt) {}

    // ─── Payload Generation ───

    public String generatePayload(String entryId, String entryPath, String parameter, String vulnType) {
        if (!config.isOobUsable()) return null;
        try {
            if ("internal".equalsIgnoreCase(config.getOobProvider())) {
                String hostname = randomLabel() + "." + stripDot(config.getOobInternalBaseDomain());
                probeMap.put(hostname, new OobProbeRecord(
                        hostname, hostname, entryId, entryPath, parameter, vulnType, System.currentTimeMillis()));
                return hostname;
            } else {
                if (api == null) return null;
                CollaboratorClient client = getOrCreateClient();
                CollaboratorPayload payload = client.generatePayload();
                if (payload == null) return null;
                String hostname = payload.toString();
                String payloadId = extractPayloadId(hostname);
                probeMap.put(payloadId, new OobProbeRecord(
                        payloadId, hostname, entryId, entryPath, parameter, vulnType, System.currentTimeMillis()));
                return hostname;
            }
        } catch (Exception e) {
            if (logger != null) logger.warn("[OOB] 生成 payload 失败: %s", e.getMessage());
            return null;
        }
    }

    public String generatePayload() {
        return generatePayload(null, null, null, "SSRF");
    }

    // ─── Interaction Polling ───

    public List<OobInteractionHit> pollInteractions() {
        if (!"collaborator".equalsIgnoreCase(config.getOobProvider())) {
            return Collections.emptyList();
        }
        if (collaboratorClient == null || probeMap.isEmpty()) {
            return Collections.emptyList();
        }
        try {
            List<Interaction> interactions = collaboratorClient.getAllInteractions();
            if (interactions == null || interactions.isEmpty()) {
                return Collections.emptyList();
            }
            List<OobInteractionHit> hits = new ArrayList<>();
            for (Interaction interaction : interactions) {
                String id = interaction.id().toString();
                if (!seenInteractionIds.add(id)) continue;

                String payloadId = extractPayloadId(id);
                OobProbeRecord probe = probeMap.get(payloadId);
                if (probe == null) {
                    for (var entry : probeMap.entrySet()) {
                        if (id.contains(entry.getKey()) || entry.getValue().fullHostname().contains(id)) {
                            probe = entry.getValue();
                            break;
                        }
                    }
                }
                if (probe != null) {
                    hits.add(new OobInteractionHit(probe,
                            interaction.type() != null ? interaction.type().name() : "UNKNOWN",
                            System.currentTimeMillis()));
                }
            }
            if (!hits.isEmpty() && logger != null) {
                logger.info("[OOB] 检测到 %d 个回连!", hits.size());
            }
            return hits;
        } catch (Exception e) {
            if (logger != null) logger.debug("[OOB] 轮询异常: %s", e.getMessage());
            return Collections.emptyList();
        }
    }

    public int getPendingProbeCount() { return probeMap.size(); }

    public boolean isCollaboratorMode() {
        return "collaborator".equalsIgnoreCase(config.getOobProvider());
    }

    // ─── Background Polling ───

    public void setInteractionCallback(Consumer<List<OobInteractionHit>> callback) {
        this.interactionCallback = callback;
    }

    public void startBackgroundPolling(long intervalMs) {
        if (!"collaborator".equalsIgnoreCase(config.getOobProvider())) return;
        if (scheduler != null) return;
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "api-sentinel-oob-poller");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(() -> {
            try {
                evictExpiredProbes();
                List<OobInteractionHit> hits = pollInteractions();
                if (!hits.isEmpty() && interactionCallback != null) {
                    interactionCallback.accept(hits);
                }
            } catch (Exception e) {
                if (logger != null) logger.debug("[OOB] 后台轮询异常: %s", e.getMessage());
            }
        }, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        if (logger != null) logger.info("[OOB] 后台轮询已启动 (间隔 %dms)", intervalMs);
    }

    public void shutdown() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    // ─── Connection Test ───

    public CompletableFuture<TestResult> testConnection() {
        return CompletableFuture.supplyAsync(() -> {
            String provider = config.getOobProvider();
            try {
                if ("internal".equalsIgnoreCase(provider)) return testInternal();
                return testCollaborator();
            } catch (Exception e) {
                return TestResult.fail("验证异常: " + e.getMessage());
            }
        });
    }

    private TestResult testCollaborator() {
        if (api == null) {
            return TestResult.fail("Burp API 不可用（Collaborator 需要 Burp 专业版）");
        }
        try {
            CollaboratorClient client = getOrCreateClient();
            CollaboratorPayload payload = client.generatePayload();
            if (payload == null) {
                return TestResult.fail("Collaborator 未返回 payload（确认专业版已登录）");
            }
            return TestResult.ok("Collaborator 可用。样本探针: " + payload, payload.toString());
        } catch (Exception e) {
            return TestResult.fail("Collaborator 不可用: " + e.getMessage());
        }
    }

    private TestResult testInternal() {
        String base = config.getOobInternalBaseDomain();
        if (base == null || base.isBlank()) {
            return TestResult.fail("未配置内部 dnslog 基础域名");
        }
        String testUrl = config.getOobInternalTestUrl();
        String sample = randomLabel() + "." + stripDot(base);
        if (testUrl == null || testUrl.isBlank()) {
            return TestResult.ok("内部 dnslog 已配置。样本探针: " + sample, sample);
        }
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(testUrl))
                    .timeout(Duration.ofSeconds(10))
                    .GET().build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            int code = resp.statusCode();
            if (code >= 200 && code < 400) {
                return TestResult.ok("内部 dnslog 平台可达 (HTTP " + code + ")。样本探针: " + sample, sample);
            }
            return TestResult.fail("内部 dnslog 测试 URL 返回 HTTP " + code);
        } catch (Exception e) {
            return TestResult.fail("内部 dnslog 测试 URL 不可达: " + e.getMessage());
        }
    }

    // ─── Internal Helpers ───

    private synchronized CollaboratorClient getOrCreateClient() {
        if (collaboratorClient == null) {
            collaboratorClient = api.collaborator().createClient();
        }
        return collaboratorClient;
    }

    private void evictExpiredProbes() {
        long now = System.currentTimeMillis();
        probeMap.entrySet().removeIf(e -> now - e.getValue().generatedAt() > PROBE_TTL_MS);
    }

    private static String extractPayloadId(String hostname) {
        int dot = hostname.indexOf('.');
        return dot > 0 ? hostname.substring(0, dot) : hostname;
    }

    private static String stripDot(String d) {
        if (d == null) return "";
        return d.endsWith(".") ? d.substring(0, d.length() - 1) : d;
    }

    private static String randomLabel() {
        return "ap" + Long.toHexString(System.nanoTime() & 0xFFFFFFFFL) + System.currentTimeMillis() % 1000;
    }

    public static final class TestResult {
        public final boolean success;
        public final String message;
        public final String samplePayload;
        private TestResult(boolean success, String message, String samplePayload) {
            this.success = success;
            this.message = message;
            this.samplePayload = samplePayload;
        }
        static TestResult ok(String msg, String sample) { return new TestResult(true, msg, sample); }
        static TestResult fail(String msg) { return new TestResult(false, msg, null); }
    }
}
