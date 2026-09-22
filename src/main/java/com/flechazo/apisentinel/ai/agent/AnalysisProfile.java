package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.agent.AnalysisStateTracker.VulnCategory;
import com.flechazo.apisentinel.model.ApiEntry;

import java.util.EnumSet;
import java.util.Set;

/**
 * Automatically selects an analysis profile based on API characteristics.
 *
 * <p>Instead of running the same analysis strategy for every endpoint, this
 * examines the HTTP method, path, and parameters to determine which vulnerability
 * categories are most likely applicable and prioritizes them.
 *
 * <p>Profiles:
 * <ul>
 *   <li><b>CRUD</b> — GET/POST/PUT/DELETE on resource paths → IDOR, SQLi, mass assignment</li>
 *   <li><b>File Ops</b> — upload/download/import/export → path traversal, XXE, file type bypass</li>
 *   <li><b>Auth/Session</b> — login/token/session paths → auth bypass, session fixation</li>
 *   <li><b>External</b> — paths with URL/fetch/proxy params → SSRF, open redirect</li>
 *   <li><b>Input-heavy</b> — POST with text/body content → XSS, SSTI, command injection</li>
 *   <li><b>Generic</b> — fallback for unrecognized patterns</li>
 * </ul>
 */
public class AnalysisProfile {

    public record ProfileResult(
            String profileName,
            Set<VulnCategory> priorityCategories,
            Set<VulnCategory> applicableCategories,
            Set<VulnCategory> lowPriorityCategories,
            String recommendation
    ) {}

    /**
     * Analyze the API entry and select the best analysis profile.
     */
    public static ProfileResult selectProfile(ApiEntry entry) {
        String path = entry.getApiPath() != null ? entry.getApiPath().toLowerCase() : "";
        String method = entry.getHttpMethod() != null ? entry.getHttpMethod().toUpperCase() : "GET";
        String request = entry.getLastRawRequest() != null ? entry.getLastRawRequest().toLowerCase() : "";

        // Score each profile
        int crudScore = 0, fileScore = 0, authScore = 0, externalScore = 0, inputScore = 0;

        // Path-based signals
        if (path.matches(".*/(users?|orders?|items?|products?|accounts?|profiles?|posts?|comments?)(/.*)?"))
            crudScore += 3;
        if (path.matches(".*/(upload|download|import|export|file|files|attachment|image|images|media)(/.*)?"))
            fileScore += 3;
        if (path.matches(".*/(auth|login|logout|token|session|register|signup|password|reset|oauth)(/.*)?"))
            authScore += 3;
        if (path.matches(".*/(proxy|fetch|redirect|webhook|callback|url|link|forward)(/.*)?"))
            externalScore += 3;
        if (path.matches(".*/(admin|manage|dashboard|setting|config)(/.*)?"))
            authScore += 1;

        // Method-based signals
        if ("PUT".equals(method) || "DELETE".equals(method) || "PATCH".equals(method))
            crudScore += 2;
        if ("POST".equals(method))
            inputScore += 1;

        // Request body signals
        if (request.contains("file") || request.contains("multipart") || request.contains("filename"))
            fileScore += 2;
        if (request.contains("url=") || request.contains("redirect") || request.contains("href"))
            externalScore += 2;
        if (request.contains("password") || request.contains("token") || request.contains("credential"))
            authScore += 2;
        if (request.contains("<") || request.contains("script") || request.contains("template"))
            inputScore += 2;

        // Determine winner
        int maxScore = Math.max(Math.max(crudScore, fileScore), Math.max(authScore, Math.max(externalScore, inputScore)));

        if (maxScore == 0) {
            return buildGenericProfile();
        }

        if (crudScore == maxScore) return buildCrudProfile();
        if (fileScore == maxScore) return buildFileProfile();
        if (authScore == maxScore) return buildAuthProfile();
        if (externalScore == maxScore) return buildExternalProfile();
        return buildInputProfile();
    }

    private static ProfileResult buildCrudProfile() {
        return new ProfileResult(
                "CRUD 资源操作",
                EnumSet.of(VulnCategory.IDOR, VulnCategory.SQL_INJECTION, VulnCategory.BUSINESS_LOGIC),
                EnumSet.of(VulnCategory.IDOR, VulnCategory.SQL_INJECTION, VulnCategory.BUSINESS_LOGIC,
                        VulnCategory.AUTH_BYPASS, VulnCategory.INFO_DISCLOSURE, VulnCategory.XSS),
                EnumSet.of(VulnCategory.SSRF, VulnCategory.XXE, VulnCategory.DESERIALIZATION),
                "CRUD 接口重点测试: 越权访问他人数据(IDOR)、SQL注入参数、业务逻辑篡改(价格/数量/状态)。"
                + "对比不同身份的响应差异确认越权。"
        );
    }

    private static ProfileResult buildFileProfile() {
        return new ProfileResult(
                "文件操作",
                EnumSet.of(VulnCategory.PATH_TRAVERSAL, VulnCategory.XXE, VulnCategory.FILE_UPLOAD),
                EnumSet.of(VulnCategory.PATH_TRAVERSAL, VulnCategory.XXE, VulnCategory.FILE_UPLOAD,
                        VulnCategory.COMMAND_INJECTION, VulnCategory.INFO_DISCLOSURE, VulnCategory.SQL_INJECTION),
                EnumSet.of(VulnCategory.SSTI, VulnCategory.OPEN_REDIRECT),
                "文件操作接口重点测试: 路径穿越(../../etc/passwd)、XXE(外部实体注入)、文件类型绕过。"
                + "检查是否有文件名/路径参数直接拼接到系统调用中。"
        );
    }

    private static ProfileResult buildAuthProfile() {
        return new ProfileResult(
                "认证/会话管理",
                EnumSet.of(VulnCategory.AUTH_BYPASS, VulnCategory.BUSINESS_LOGIC, VulnCategory.INFO_DISCLOSURE),
                EnumSet.of(VulnCategory.AUTH_BYPASS, VulnCategory.BUSINESS_LOGIC, VulnCategory.INFO_DISCLOSURE,
                        VulnCategory.SQL_INJECTION, VulnCategory.IDOR, VulnCategory.CSRF),
                EnumSet.of(VulnCategory.XXE, VulnCategory.PATH_TRAVERSAL),
                "认证接口重点测试: 绕过认证(空密码/SQLi注入登录/默认凭证)、会话固定、权限提升。"
                + "检查 token 生成是否可预测、是否存在暴力破解风险。"
        );
    }

    private static ProfileResult buildExternalProfile() {
        return new ProfileResult(
                "外部调用/重定向",
                EnumSet.of(VulnCategory.SSRF, VulnCategory.OPEN_REDIRECT),
                EnumSet.of(VulnCategory.SSRF, VulnCategory.OPEN_REDIRECT, VulnCategory.SQL_INJECTION,
                        VulnCategory.XSS, VulnCategory.INFO_DISCLOSURE),
                EnumSet.of(VulnCategory.DESERIALIZATION, VulnCategory.FILE_UPLOAD),
                "外部调用接口重点测试: SSRF(内网地址/云元数据169.254.169.254)、开放重定向(外域跳转)。"
                + "尝试 localhost/127.0.0.1/169.254.169.254 等内网地址作为 URL 参数值。"
        );
    }

    private static ProfileResult buildInputProfile() {
        return new ProfileResult(
                "输入密集型",
                EnumSet.of(VulnCategory.XSS, VulnCategory.SQL_INJECTION, VulnCategory.SSTI),
                EnumSet.of(VulnCategory.XSS, VulnCategory.SQL_INJECTION, VulnCategory.SSTI,
                        VulnCategory.COMMAND_INJECTION, VulnCategory.IDOR, VulnCategory.BUSINESS_LOGIC),
                EnumSet.of(VulnCategory.FILE_UPLOAD, VulnCategory.OPEN_REDIRECT),
                "输入密集型接口重点测试: 反射/存储型XSS、SQL注入、SSTI模板注入。"
                + "检查用户输入是否直接拼接进 SQL/HTML/模板/系统命令。"
        );
    }

    private static ProfileResult buildGenericProfile() {
        return new ProfileResult(
                "通用分析",
                EnumSet.of(VulnCategory.SQL_INJECTION, VulnCategory.XSS, VulnCategory.IDOR),
                EnumSet.of(VulnCategory.SQL_INJECTION, VulnCategory.XSS, VulnCategory.IDOR,
                        VulnCategory.SSRF, VulnCategory.AUTH_BYPASS, VulnCategory.INFO_DISCLOSURE,
                        VulnCategory.BUSINESS_LOGIC),
                EnumSet.of(VulnCategory.DESERIALIZATION, VulnCategory.XXE, VulnCategory.SSTI),
                "未匹配特定模式，执行通用安全分析。优先检查 SQL 注入、XSS、越权三大类。"
        );
    }

    /**
     * Build a system prompt injection for the analysis profile.
     * Called after heuristic_scan to guide the Agent's analysis strategy.
     */
    public static String buildProfilePrompt(ProfileResult profile) {
        StringBuilder sb = new StringBuilder();
        sb.append("【分析 Profile】基于接口特征自动选择: ").append(profile.profileName()).append("\n");
        sb.append("- 重点测试: ");
        profile.priorityCategories().forEach(c -> sb.append(c.displayName()).append(", "));
        sb.setLength(sb.length() - 2); // remove trailing ", "
        sb.append("\n- 降低优先: ");
        profile.lowPriorityCategories().forEach(c -> sb.append(c.displayName()).append(", "));
        sb.setLength(sb.length() - 2);
        sb.append("\n- 建议: ").append(profile.recommendation()).append("\n");
        sb.append("- 预计 15-20 轮完成分析\n\n");
        return sb.toString();
    }
}
