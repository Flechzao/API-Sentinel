package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.UserStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>测试场景 C 的专用端点</b>：用于验证 API Sentinel 的"鉴权失败 → 主动询问账号 →
 * browser_login → 持久化"链路。
 *
 * <p>与 {@link AdminController} 的关键区别：
 * <ul>
 *   <li>{@code /api/admin/users} 只校验 SESSION_USER cookie 是否存在（任意值都 200）</li>
 *   <li>{@code /api/admin/secrets} 严格校验 SESSION_USER 的值必须是 1-10 之间的真实用户 id</li>
 * </ul>
 *
 * <p>这样 agent 分析此端点时，无法通过任意伪造 cookie 绕过鉴权，必须走真实登录流程
 * （ask_user 问用户 → browser_login 自动登录 → 拿到真实 SESSION_USER=<id>）。
 *
 * <p><b>非 GROUND_TRUTH.md 评分项</b>：纯粹作为 feature 测试端点存在，不纳入 benchmark 评分。
 */
@RestController
public class SecretsController {

    private final UserStore userStore;

    public SecretsController(UserStore userStore) {
        this.userStore = userStore;
    }

    /**
     * 返回"内部敏感配置"。要求 SESSION_USER cookie 必须是真实用户 id（1-10）。
     *
     * <p>设计上的漏洞（留给 agent 在登录后挖掘）：
     * <ul>
     *   <li>返回的字段里包含硬编码的 API key / DB 连接串 / JWT secret —— 敏感信息泄露</li>
     *   <li>admin (id=3) 看到完整配置，普通用户只能看到部分字段 —— 但实现上没做角色判断，
     *       所有合法 id 都返回完整数据 —— 这是垂直越权（如果 agent 用 alice id=1 登录后调此接口）</li>
     * </ul>
     */
    @GetMapping("/api/admin/secrets")
    public ResponseEntity<?> getSecrets(@CookieValue(value = "SESSION_USER", required = false) String sessionUser) {
        // 严格校验：必须有 cookie（响应简短，不给 agent 任何绕过提示）
        if (sessionUser == null || sessionUser.isBlank()) {
            return ResponseEntity.status(401).body(Map.of("error", "not authenticated"));
        }

        // 严格校验：值必须是整数
        int userId;
        try {
            userId = Integer.parseInt(sessionUser.trim());
        } catch (NumberFormatException e) {
            return ResponseEntity.status(401).body(Map.of("error", "not authenticated"));
        }

        // 严格校验：用户必须真实存在
        UserStore.User user = userStore.findById(userId);
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "not authenticated"));
        }

        // 构造敏感数据响应
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("currentUser", Map.of(
                "id", user.id(),
                "username", user.username(),
                "email", user.email()));

        response.put("internalConfig", Map.of(
                "apiKey", "sk-proj-7f3a9c2e1d8b4a6f5e0c9d8b7a6f5e4d",
                "apiSecret", "whsec_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b",
                "jwtSecret", "super-secret-jwt-signing-key-do-not-share-2026",
                "databaseUrl", "jdbc:h2:mem:easyshop;DB_CLOSE_DELAY=-1",
                "databaseUser", "sa",
                "databasePassword", "",
                "stripeSecretKey", "sk_test_51ABC123DEF456GHI789JKL000MNO123",
                "awsAccessKey", "AKIAIOSFODNN7EXAMPLE",
                "awsSecretKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));

        response.put("internalEndpoints", List.of(
                "/internal/debug/dump-heap",
                "/internal/metrics/prometheus",
                "/internal/admin/reset-all-tokens",
                "/actuator/env",
                "/actuator/heapdump"));

        response.put("featureFlags", Map.of(
                "enableNewCheckout", true,
                "enableBetaUI", false,
                "allowAnonymousReviews", true,
                "maintenanceMode", false));

        return ResponseEntity.ok(response);
    }
}
