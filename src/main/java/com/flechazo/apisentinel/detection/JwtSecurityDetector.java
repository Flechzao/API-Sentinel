package com.flechazo.apisentinel.detection;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** JWT 安全检测器——被动检测 alg:none / 缺过期 / 内嵌 jwk / jku/x5u/kid 注入等。 */
public class JwtSecurityDetector {

    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]*");

    private static final Set<String> SENSITIVE_PAYLOAD_KEYS = Set.of(
            "password", "passwd", "pwd", "secret", "credit_card", "card_number",
            "ssn", "phone", "mobile", "id_card", "idcard", "bank_account");

    private static final Set<String> WEAK_ALGORITHMS = Set.of("none", "HS256");

    public static List<HeuristicDetector.HeuristicFinding> detectJwtIssues(String rawResponse) {
        List<HeuristicDetector.HeuristicFinding> findings = new ArrayList<>();
        if (rawResponse == null || rawResponse.isEmpty()) return findings;

        Matcher m = JWT_PATTERN.matcher(rawResponse);
        // Process ALL JWTs in the response (e.g. access + refresh tokens),
        // not just the first one. Dedupe identical findings at the end.
        while (m.find()) {
            String jwt = m.group();
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) continue;

            String headerJson = decodeBase64Url(parts[0]);
            String payloadJson = decodeBase64Url(parts[1]);
            if (headerJson == null || payloadJson == null) continue;

            checkAlgorithm(headerJson, findings);
            checkHeaderInjection(headerJson, findings);
            checkExpiration(payloadJson, findings);
            checkSensitiveData(payloadJson, findings);
            checkPrivilegedClaims(payloadJson, findings);

            if (parts.length == 3 && parts[2].isEmpty()) {
                findings.add(new HeuristicDetector.HeuristicFinding(
                        "HIGH", "JWT 安全", "JWT 缺少签名",
                        "JWT 签名部分为空，token 未被签名验证",
                        "确保所有 JWT 都包含有效签名并在服务端验证"
                ));
            }
        }
        return dedupe(findings);
    }

    /**
     * Detect JWT header parameters that enable key-injection attacks
     * (jku / jwk / x5u / kid with traversal or injection characters).
     * CVE-2018-0114 (jwk), and kid path-traversal/SQLi are well-known vectors.
     */
    private static void checkHeaderInjection(String headerJson, List<HeuristicDetector.HeuristicFinding> findings) {
        String lower = headerJson.toLowerCase();
        if (lower.contains("\"jku\"")) {
            findings.add(new HeuristicDetector.HeuristicFinding(
                    "MEDIUM", "JWT 安全", "JWT Header 含 jku 字段",
                    "JWT Header 包含 jku (JWK Set URL)，攻击者可指向自有密钥服务器伪造 token",
                    "服务端不应信任 token 中的 jku，应使用预置密钥"
            ));
        }
        if (lower.contains("\"jwk\"")) {
            findings.add(new HeuristicDetector.HeuristicFinding(
                    "MEDIUM", "JWT 安全", "JWT Header 内嵌 jwk",
                    "JWT Header 内嵌 JWK 公钥，攻击者可嵌入自有公钥伪造 token (CVE-2018-0114)",
                    "服务端不应信任 token 内嵌的 jwk，应使用预置公钥"
            ));
        }
        if (lower.contains("\"x5u\"") || lower.contains("\"x5c\"")) {
            findings.add(new HeuristicDetector.HeuristicFinding(
                    "MEDIUM", "JWT 安全", "JWT Header 含 x5u/x5c 字段",
                    "JWT Header 包含 X.509 证书 URL/链，可能被用于密钥注入",
                    "服务端不应信任 token 中的 x5u/x5c，应使用预置证书"
            ));
        }
        String kid = extractJsonStringValue(headerJson, "kid");
        if (kid != null) {
            String kidLower = kid.toLowerCase();
            if (kid.contains("../") || kid.contains("..\\") || kidLower.contains("union")
                    || kidLower.contains("select ") || kidLower.contains("'")
                    || kidLower.contains("\"") || kidLower.contains(";")
                    || kidLower.contains(" or ")) {
                findings.add(new HeuristicDetector.HeuristicFinding(
                        "MEDIUM", "JWT 安全", "JWT kid 字段含可疑字符",
                        "JWT kid 字段包含路径遍历或注入特征: " + truncate(kid, 60),
                        "服务端对 kid 做白名单校验，勿直接拼接进文件路径/SQL"
                ));
            }
        }
    }

    private static List<HeuristicDetector.HeuristicFinding> dedupe(
            List<HeuristicDetector.HeuristicFinding> findings) {
        List<HeuristicDetector.HeuristicFinding> out = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (var f : findings) {
            String key = f.risk() + "|" + f.title() + "|" + f.evidence();
            if (seen.add(key)) out.add(f);
        }
        return out;
    }

    private static String truncate(String s, int maxLen) {
        return (s == null || s.length() <= maxLen) ? s : s.substring(0, maxLen) + "...";
    }

    private static void checkAlgorithm(String headerJson, List<HeuristicDetector.HeuristicFinding> findings) {
        String alg = extractJsonStringValue(headerJson, "alg");
        if (alg == null) return;

        if ("none".equalsIgnoreCase(alg)) {
            findings.add(new HeuristicDetector.HeuristicFinding(
                    "HIGH", "JWT 安全", "JWT 使用 alg:none",
                    "JWT Header 声明 alg: none，攻击者可伪造任意 token",
                    "服务端必须拒绝 alg:none，强制使用 RS256/ES256 等安全算法"
            ));
        } else if ("HS256".equalsIgnoreCase(alg)) {
            findings.add(new HeuristicDetector.HeuristicFinding(
                    "LOW", "JWT 安全", "JWT 使用 HS256 对称算法",
                    "JWT 使用 HS256 对称签名，弱密钥可被暴力破解",
                    "建议使用 RS256/ES256 非对称算法，或确保 HS256 密钥足够复杂 (≥256 bit)"
            ));
        }
    }

    private static void checkExpiration(String payloadJson, List<HeuristicDetector.HeuristicFinding> findings) {
        Long exp = extractJsonLongValue(payloadJson, "exp");
        Long iat = extractJsonLongValue(payloadJson, "iat");

        if (exp == null) {
            findings.add(new HeuristicDetector.HeuristicFinding(
                    "MEDIUM", "JWT 安全", "JWT 缺少过期时间",
                    "JWT Payload 中没有 exp 字段，token 永不过期",
                    "设置合理的过期时间 (建议 ≤24 小时)，配合 refresh token 机制"
            ));
            return;
        }

        if (iat != null) {
            long durationDays = (exp - iat) / 86400;
            if (durationDays > 7) {
                findings.add(new HeuristicDetector.HeuristicFinding(
                        "LOW", "JWT 安全", "JWT 有效期过长",
                        "JWT 有效期约 " + durationDays + " 天 (建议 ≤7 天)",
                        "缩短 token 有效期，使用 refresh token 进行续期"
                ));
            }
        }
    }

    private static void checkSensitiveData(String payloadJson, List<HeuristicDetector.HeuristicFinding> findings) {
        String lower = payloadJson.toLowerCase();
        for (String key : SENSITIVE_PAYLOAD_KEYS) {
            if (lower.contains("\"" + key + "\"")) {
                findings.add(new HeuristicDetector.HeuristicFinding(
                        "MEDIUM", "JWT 安全", "JWT Payload 包含敏感字段",
                        "JWT Payload 中存在敏感字段: " + key,
                        "JWT Payload 可被 Base64 解码查看，不应包含敏感信息"
                ));
                return;
            }
        }
    }

    private static void checkPrivilegedClaims(String payloadJson, List<HeuristicDetector.HeuristicFinding> findings) {
        String lower = payloadJson.toLowerCase();
        if ((lower.contains("\"role\"") || lower.contains("\"roles\""))
                && (lower.contains("\"admin\"") || lower.contains("\"superadmin\"") || lower.contains("\"root\""))) {
            findings.add(new HeuristicDetector.HeuristicFinding(
                    "INFO", "JWT 安全", "JWT 包含高权限角色声明",
                    "JWT Payload 中包含管理员角色声明，确保服务端验证而非仅信任 token",
                    "权限校验应在服务端进行，不应仅依赖 JWT 中的 role 声明"
            ));
        }
    }

    private static String decodeBase64Url(String encoded) {
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(encoded);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static String extractJsonStringValue(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static Long extractJsonLongValue(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)");
        Matcher m = p.matcher(json);
        if (m.find()) {
            try { return Long.parseLong(m.group(1)); } catch (NumberFormatException e) { return null; }
        }
        return null;
    }
}
