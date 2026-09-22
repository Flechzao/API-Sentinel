package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.auth.AuthParamIdentifier;
import com.flechazo.apisentinel.auth.AuthTestExecutor;
import com.flechazo.apisentinel.auth.AuthTestResult;
import com.flechazo.apisentinel.auth.SessionDiscovery;
import com.flechazo.apisentinel.auth.SessionInfo;
import com.google.gson.JsonObject;

import java.util.List;
import java.util.Map;

public class AuthBypassTool implements AgentTool {

    private final ToolContext ctx;
    private AuthTestResult lastResult;

    public AuthBypassTool(ToolContext ctx) {
        this.ctx = ctx;
    }

    public AuthTestResult getLastResult() { return lastResult; }

    @Override
    public String name() { return "test_auth_bypass"; }

    @Override
    public String description() {
        return "Run automated authorization bypass testing. Discovers multiple sessions from proxy history, "
             + "identifies auth parameters (cookies/headers), then systematically swaps credentials between "
             + "sessions to detect broken access control vulnerabilities. Sends multiple HTTP requests. "
             + "Free, no AI cost.";
    }

    @Override
    public JsonObject inputSchema() {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        schema.add("properties", new JsonObject());
        return schema;
    }

    @Override
    public String execute(String argumentsJson) {
        if (ctx.montoyaApi() == null) {
            lastResult = AuthTestResult.skipped("Burp API not available");
            return "{\"verdict\": \"SKIPPED\", \"reason\": \"Burp API not available\"}";
        }

        try {
            var entry = ctx.entry();

            // Step 1: Discover sessions. Three-level fallback so a single-account
            // visit to the target endpoint no longer forces manual cookie setup:
            //   (a) sessions that hit this exact endpoint (>=2)
            //   (b) sessions seen anywhere on the same domain (>=2)
            //   (c) manually configured cookies from settings
            SessionDiscovery discovery = new SessionDiscovery(ctx.montoyaApi());
            List<SessionInfo> sessions = discovery.discoverSessions(entry);
            String sessionSource = "endpoint";

            if (sessions.size() < 2 && entry.getDomain() != null && !entry.getDomain().isBlank()) {
                List<SessionInfo> domainSessions = discovery.discoverDomainSessions(entry.getDomain());
                if (domainSessions.size() >= 2) {
                    sessions = domainSessions;
                    sessionSource = "domain";
                }
            }

            SessionInfo sessionA;
            SessionInfo sessionB;

            // Check manual sessions first — user-configured is more reliable
            // than auto-discovered, and supports 3 sessions for multi-tier testing.
            boolean useManualPairwise = false;
            if (ctx.pipelineConfig() != null && ctx.pipelineConfig().hasManualSessions()) {
                useManualPairwise = true;
            }

            if (useManualPairwise) {
                // Multi-session pairwise execution (supports 2 or 3 sessions)
                AuthTestExecutor executor = new AuthTestExecutor(ctx.montoyaApi(), ctx.provider(),
                        ctx.pipelineConfig().aiAuthArbitrationEnabled());
                String targetDomain = entry.getDomain() != null ? entry.getDomain() : "";
                lastResult = executor.executePairwise(ctx.pipelineConfig().manualSessionConfigs(), targetDomain);

                String text = lastResult.toPromptText();
                if (ctx.pipelineConfig() != null) {
                    String dir = inferPrivilegeDirection(
                            ctx.pipelineConfig().manualSessionALabel(),
                            ctx.pipelineConfig().manualSessionBLabel());
                    if (dir != null) {
                        text = "⚠ 权限方向推断: " + dir
                                + "（若低权会话获得高权数据则为垂直越权）\n" + text;
                    }
                }
                return text;
            }

            // Auto-discovery fallback: sessions that hit this exact endpoint (>=2),
            // then sessions seen anywhere on the same domain (>=2).
            if (sessions.size() >= 2) {
                sessions.sort((a, b) -> Integer.compare(b.getRequests().size(), a.getRequests().size()));
                sessionA = sessions.get(0);
                sessionB = sessions.get(1);
            } else if (sessions.size() < 2 && entry.getDomain() != null && !entry.getDomain().isBlank()) {
                // Already tried domain discovery above; if still < 2, give up
                lastResult = AuthTestResult.skipped("Need at least 2 sessions for auth bypass testing");
                return "{\"verdict\": \"SKIPPED\", \"reason\": \"Only " + sessions.size()
                     + " session(s) found on this endpoint and its domain. "
                     + "Browse the target with a second account (through the Burp proxy) so two distinct "
                     + "sessions can be auto-discovered, or configure manual sessions in Settings → Auth.\"}";
            } else {
                lastResult = AuthTestResult.skipped("Need at least 2 sessions for auth bypass testing");
                return "{\"verdict\": \"SKIPPED\", \"reason\": \"Only " + sessions.size()
                     + " session(s) found. Configure manual sessions in Settings → Auth.\"}";
            }

            // Step 2: Identify auth parameters
            List<String> authCookieKeys = AuthParamIdentifier.identifyAuthCookieKeys(sessionA, sessionB);
            List<String> authHeaderKeys = AuthParamIdentifier.identifyAuthHeaders(sessionA, sessionB);

            if (authCookieKeys.isEmpty() && authHeaderKeys.isEmpty()) {
                lastResult = AuthTestResult.skipped("No differing auth parameters found between sessions");
                return "{\"verdict\": \"SKIPPED\", \"reason\": \"No differing auth parameters between sessions\"}";
            }

            // Step 3: Execute auth bypass test (with optional LLM arbitration)
            AuthTestExecutor executor = new AuthTestExecutor(ctx.montoyaApi(), ctx.provider(),
                    ctx.pipelineConfig() == null || ctx.pipelineConfig().aiAuthArbitrationEnabled());
            lastResult = executor.execute(sessionA, sessionB, authCookieKeys, authHeaderKeys);

            String text = lastResult.toPromptText();
            if ("domain".equals(sessionSource)) {
                text = "（会话来源: 同域名其它接口流量自动发现，共 " + sessions.size()
                        + " 个会话，取请求数最多的两个）\n" + text;
            }
            // Annotate vertical-escalation direction when manual session labels
            // indicate role separation (full UI privilege tagging is a future
            // enhancement; this heuristic uses the existing label fields).
            if (ctx.pipelineConfig() != null) {
                String dir = inferPrivilegeDirection(
                        ctx.pipelineConfig().manualSessionALabel(),
                        ctx.pipelineConfig().manualSessionBLabel());
                if (dir != null) {
                    text = "⚠ 权限方向推断: " + dir
                            + "（若低权会话获得高权数据则为垂直越权）\n" + text;
                }
            }
            return text;
        } catch (Exception e) {
            lastResult = AuthTestResult.skipped("Error: " + e.getMessage());
            return "{\"verdict\": \"SKIPPED\", \"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /** Infer HIGH/LOW privilege from a session label, or null if unknown. */
    private static String inferPrivilegeLevel(String label) {
        if (label == null || label.isBlank()) return null;
        String l = label.toLowerCase();
        if (l.contains("admin") || l.contains("管理员") || l.contains("高权")
                || l.contains("root") || l.contains("super")) return "HIGH";
        if (l.contains("user") || l.contains("普通") || l.contains("低权")
                || l.contains("guest") || l.contains("low")) return "LOW";
        return null;
    }

    private static String inferPrivilegeDirection(String labelA, String labelB) {
        String a = inferPrivilegeLevel(labelA);
        String b = inferPrivilegeLevel(labelB);
        if (a == null || b == null || a.equals(b)) return null;
        return "会话A=" + a + ", 会话B=" + b;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
