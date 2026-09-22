package com.flechazo.apisentinel.mcp;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * MCP 服务器安全扫描器
 *
 * 发现和分析暴露的 Model Context Protocol (MCP) 服务器：
 * - 自动发现 MCP 端点（/.well-known/mcp, /mcp, /api/mcp 等）
 * - 检测认证缺失（100% 的暴露 MCP 服务器缺少认证）
 * - 枚举可用工具
 * - 评估安全风险
 *
 * 参考：
 * - MCP-Scanner (knostic/MCP-Scanner) — 1,862 个暴露服务器，100% 无认证
 * - mcp-audit — MCP 服务器安全审计
 *
 * @since 1.2.0
 */
public class McpSecurityScanner {

    private static final String[] MCP_ENDPOINTS = {
            "/.well-known/mcp",
            "/mcp",
            "/api/mcp",
            "/mcp/v1",
            "/api/v1/mcp",
            "/mcp-server",
            "/mcp/config"
    };

    /** P1 安全加固：单次扫描总时长上限（ms）。7 端点 × (5s connect + 5s read) 最坏 70s，
     *  会阻塞 Agent loop；加上总截止线后即使全部超时也不会超过此值。 */
    static final long MAX_TOTAL_SCAN_MS = 30_000;

    private final LeveledLogger logger;

    public McpSecurityScanner(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * 扫描目标域名的 MCP 服务器
     *
     * @param baseUrl 目标基础 URL（如 https://example.com）
     * @return 扫描结果
     */
    public ScanResult scan(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return ScanResult.error("baseUrl is required");
        }

        // Normalize URL
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            baseUrl = "https://" + baseUrl;
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }

        // P1 安全加固：SSRF 防护——解析主机，拒绝指向云元数据/链路本地等地址的目标。
        // 背景：此扫描器在 AI Agent 上下文中运行，target_url 可被 prompt injection 篡改，
        // 若放行 169.254.169.254 等元数据地址，攻击者可借扫描器窃取云凭据。
        String host = extractHost(baseUrl);
        if (host != null && isSsrfBlocked(host)) {
            if (logger != null) {
                logger.warn("[McpScanner] Blocked SSRF target: %s resolves to a metadata/link-local address", host);
            }
            return ScanResult.error("Blocked: target host resolves to a cloud metadata or link-local address (SSRF protection). Refusing to scan: " + host);
        }

        List<McpEndpoint> endpoints = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        if (logger != null) {
            logger.debug("[McpScanner] Scanning %s for MCP endpoints...", baseUrl);
        }

        // P3 性能：7 端点并发探测。串行最坏 7×(5s connect + 5s read)=70s（此前已被 30s 总截止限制），
        // 并发后最坏降至约单批 10s。保留总截止线与 SSRF 防护。
        long remainingMs = MAX_TOTAL_SCAN_MS;
        int threads = Math.min(MCP_ENDPOINTS.length, 4);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Callable<ProbeResult>> tasks = new ArrayList<>(MCP_ENDPOINTS.length);
            for (String path : MCP_ENDPOINTS) {
                String url = baseUrl + path;
                tasks.add(() -> {
                    try {
                        return new ProbeResult(probeEndpoint(url), null);
                    } catch (Exception e) {
                        return new ProbeResult(null, url + ": " + e.getMessage());
                    }
                });
            }
            // invokeAll 在剩余预算内等待全部完成；超时则取消未完成任务
            List<Future<ProbeResult>> futures = pool.invokeAll(tasks, remainingMs, TimeUnit.MILLISECONDS);
            boolean aborted = false;
            for (Future<ProbeResult> f : futures) {
                if (f.isCancelled()) {
                    if (!aborted) {
                        errors.add("scan aborted: total scan time exceeded " + MAX_TOTAL_SCAN_MS + "ms limit");
                        aborted = true;
                    }
                    continue;
                }
                try {
                    ProbeResult pr = f.get();
                    if (pr.error != null) {
                        errors.add(pr.error);
                        if (logger != null) {
                            logger.debug("[McpScanner] Probe failed: %s", pr.error);
                        }
                    } else if (pr.endpoint != null) {
                        endpoints.add(pr.endpoint);
                        if (logger != null) {
                            logger.debug("[McpScanner] Found: %s (auth: %s, tools: %d)",
                                    pr.endpoint.url(), pr.endpoint.authRequired() ? "yes" : "NO",
                                    pr.endpoint.toolCount());
                        }
                    }
                } catch (Exception e) {
                    errors.add("probe error: " + e.getMessage());
                }
            }
            if (aborted && logger != null) {
                logger.warn("[McpScanner] Total scan deadline reached, some endpoints aborted");
            }
        } catch (InterruptedException e) {
            errors.add("scan interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        } finally {
            pool.shutdownNow();
        }

        // 按 URL 排序保证输出确定性（并发探测完成顺序不确定）
        endpoints.sort(Comparator.comparing(McpEndpoint::url));

        if (logger != null) {
            logger.debug("[McpScanner] Scan complete: %d endpoints found", endpoints.size());
        }

        return new ScanResult(baseUrl, endpoints, errors);
    }

    /** 单次探测的结果持有者（端点或错误，二选一）。 */
    private record ProbeResult(McpEndpoint endpoint, String error) {}

    /**
     * P1 SSRF 防护：判断主机解析后的地址是否落在被封锁范围。
     * <ul>
     *   <li>{@code isAnyLocal()} — 0.0.0.0 / :: 通配地址</li>
     *   <li>{@code isLinkLocal()} — 169.254/16（AWS/GCP/Azure 元数据）、fe80::</li>
     *   <li>已知云元数据 IP：100.100.100.200（阿里云 ECS 元数据）</li>
     * </ul>
     * 放行 loopback（127/8、::1）与站点本地段（10/8、172.16/12、192.168/16）——
     * 扫描器由操作者显式指定目标，渗透测试中内网/本机是合法目标，仅拦截云元数据滥用面。
     * DNS 不可解析时放行（让后续 probe 自然失败，不在此误报）。
     */
    static boolean isSsrfBlocked(String host) {
        if (host == null || host.isBlank()) return false;
        try {
            for (InetAddress addr : InetAddress.getAllByName(host)) {
                if (isBlockedAddress(addr)) return true;
            }
        } catch (UnknownHostException e) {
            return false;
        }
        return false;
    }

    private static boolean isBlockedAddress(InetAddress addr) {
        if (addr.isAnyLocalAddress() || addr.isLinkLocalAddress()) return true;
        String ip = addr.getHostAddress();
        // 阿里云 ECS 元数据 100.100.100.200 不在 isSiteLocal/isLinkLocal 范围内，单独拦截
        return "100.100.100.200".equals(ip);
    }

    /** 从 URL 中提取主机名（不含端口），用于 SSRF 解析校验。 */
    private static String extractHost(String url) {
        try {
            URL u = new URL(url);
            return u.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 探测单个 MCP 端点
     */
    private McpEndpoint probeEndpoint(String url) throws IOException {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("User-Agent", "API-Sentinel-MCP-Scanner/1.0");
            conn.setRequestProperty("Accept", "application/json");

            int status = conn.getResponseCode();

            // Check if it's a valid MCP endpoint
            if (status == 200 || status == 401 || status == 403) {
                boolean authRequired = (status == 401 || status == 403);
                String contentType = conn.getContentType();

                // Try to read response and extract tool count
                int toolCount = 0;
                String serverInfo = null;

                if (status == 200) {
                    try {
                        String response = new String(conn.getInputStream().readAllBytes());
                        toolCount = extractToolCount(response);
                        serverInfo = extractServerInfo(response);
                    } catch (Exception ignored) {}
                }

                // Check for security headers
                boolean hasSecurityHeaders = checkSecurityHeaders(conn);

                return new McpEndpoint(
                        url,
                        status,
                        authRequired,
                        toolCount,
                        contentType,
                        serverInfo,
                        hasSecurityHeaders
                );
            }

            return null; // Not an MCP endpoint

        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * 从响应中提取工具数量
     */
    private int extractToolCount(String response) {
        // Look for "tools" array in JSON response
        if (response.contains("\"tools\"")) {
            // Simple heuristic: count occurrences of tool definitions
            int count = 0;
            int idx = 0;
            while ((idx = response.indexOf("\"name\"", idx)) != -1) {
                count++;
                idx += 6;
            }
            return count;
        }
        return 0;
    }

    /**
     * 提取服务器信息
     */
    private String extractServerInfo(String response) {
        // Look for server version/name in response
        if (response.contains("\"server\"")) {
            int start = response.indexOf("\"server\"");
            int end = Math.min(start + 200, response.length());
            return response.substring(start, end);
        }
        return null;
    }

    /**
     * 检查安全响应头
     */
    private boolean checkSecurityHeaders(HttpURLConnection conn) {
        String[] securityHeaders = {
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options"
        };

        int found = 0;
        for (String header : securityHeaders) {
            if (conn.getHeaderField(header) != null) {
                found++;
            }
        }

        return found >= 2; // At least 2 security headers
    }

    /**
     * MCP 端点信息
     */
    public record McpEndpoint(
            String url,
            int statusCode,
            boolean authRequired,
            int toolCount,
            String contentType,
            String serverInfo,
            boolean hasSecurityHeaders
    ) {
        /** 风险评估 */
        public String riskLevel() {
            if (!authRequired && toolCount > 0) return "CRITICAL";
            if (!authRequired) return "HIGH";
            if (!hasSecurityHeaders) return "MEDIUM";
            return "LOW";
        }

        /** 生成安全建议 */
        public String recommendation() {
            StringBuilder sb = new StringBuilder();
            if (!authRequired) {
                sb.append("⚠️ CRITICAL: No authentication required! ");
                sb.append("Add authentication (API key, OAuth, or JWT). ");
            }
            if (!hasSecurityHeaders) {
                sb.append("Add security headers (HSTS, CSP, X-Frame-Options). ");
            }
            if (toolCount > 0) {
                sb.append("Review exposed tools for sensitive operations. ");
            }
            if (sb.length() == 0) {
                sb.append("Configuration appears secure.");
            }
            return sb.toString();
        }
    }

    /**
     * 扫描结果
     */
    public record ScanResult(
            String baseUrl,
            List<McpEndpoint> endpoints,
            List<String> errors
    ) {
        public boolean hasEndpoints() {
            return endpoints != null && !endpoints.isEmpty();
        }

        public int criticalCount() {
            return (int) endpoints.stream()
                    .filter(e -> "CRITICAL".equals(e.riskLevel()))
                    .count();
        }

        public static ScanResult error(String message) {
            return new ScanResult(null, List.of(), List.of(message));
        }

        /** 转换为 JSON */
        public JsonObject toJson() {
            JsonObject obj = new JsonObject();
            obj.addProperty("base_url", baseUrl);
            obj.addProperty("endpoints_found", endpoints.size());
            obj.addProperty("critical_risk", criticalCount());

            JsonArray endpointsArr = new JsonArray();
            for (McpEndpoint ep : endpoints) {
                JsonObject eo = new JsonObject();
                eo.addProperty("url", ep.url());
                eo.addProperty("status_code", ep.statusCode());
                eo.addProperty("auth_required", ep.authRequired());
                eo.addProperty("tool_count", ep.toolCount());
                eo.addProperty("risk_level", ep.riskLevel());
                eo.addProperty("recommendation", ep.recommendation());
                endpointsArr.add(eo);
            }
            obj.add("endpoints", endpointsArr);

            if (!errors.isEmpty()) {
                JsonArray errorsArr = new JsonArray();
                errors.forEach(errorsArr::add);
                obj.add("errors", errorsArr);
            }

            return obj;
        }
    }
}
