package com.flechazo.apisentinel.detection;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

/**
 * 统一攻击类型分类体系
 *
 * 参考 OWASP API Security Top 10 (2023) + BurpAPI 15 种攻击类型 + 行业最佳实践。
 * 每个攻击类型包含：
 *   - 标识符 (id)
 *   - 名称 (name)
 *   - 描述 (description)
 *   - OWASP API Top 10 映射
 *   - 严重性级别 (severity)
 *   - 对应的检测器/工具 (detectors)
 *   - Payload 类别 (payloadCategories)
 *
 * @since 1.2.0
 */
public final class AttackType {

    // ======================== OWASP API Security Top 10 (2023) ========================

    /** API1:2023 - Broken Object Level Authorization (BOLA/IDOR) */
    public static final String BOLA = "BOLA";

    /** API2:2023 - Broken Authentication */
    public static final String BROKEN_AUTH = "BROKEN_AUTH";

    /** API3:2023 - Broken Object Property Level Authorization */
    public static final String BOPLA = "BOPLA";

    /** API4:2023 - Unrestricted Resource Consumption */
    public static final String RESOURCE_CONSUMPTION = "RESOURCE_CONSUMPTION";

    /** API5:2023 - Broken Function Level Authorization */
    public static final String BROKEN_FUNCTION_AUTH = "BROKEN_FUNCTION_AUTH";

    /** API6:2023 - Unrestricted Access to Sensitive Business Flows */
    public static final String SENSITIVE_BUSINESS_FLOW = "SENSITIVE_BUSINESS_FLOW";

    /** API7:2023 - Server Side Request Forgery (SSRF) */
    public static final String SSRF = "SSRF";

    /** API8:2023 - Security Misconfiguration */
    public static final String SECURITY_MISCONFIG = "SECURITY_MISCONFIG";

    /** API9:2023 - Improper Inventory Management */
    public static final String IMPROPER_INVENTORY = "IMPROPER_INVENTORY";

    /** API10:2023 - Unsafe Consumption of APIs */
    public static final String UNSAFE_CONSUMPTION = "UNSAFE_CONSUMPTION";

    // ======================== 传统 Web 漏洞 ========================

    /** SQL Injection */
    public static final String SQL_INJECTION = "SQL_INJECTION";

    /** NoSQL Injection */
    public static final String NOSQL_INJECTION = "NOSQL_INJECTION";

    /** Cross-Site Scripting (XSS) */
    public static final String XSS = "XSS";

    /** Cross-Site Request Forgery (CSRF) */
    public static final String CSRF = "CSRF";

    /** Path Traversal / Directory Traversal */
    public static final String PATH_TRAVERSAL = "PATH_TRAVERSAL";

    /** Server-Side Template Injection (SSTI) */
    public static final String SSTI = "SSTI";

    /** XML External Entity (XXE) */
    public static final String XXE = "XXE";

    /** Insecure Deserialization */
    public static final String DESERIALIZATION = "DESERIALIZATION";

    /** Open Redirect */
    public static final String OPEN_REDIRECT = "OPEN_REDIRECT";

    /** HTTP Request Smuggling */
    public static final String REQUEST_SMUGGLING = "REQUEST_SMUGGLING";

    /** GraphQL Specific Issues */
    public static final String GRAPHQL = "GRAPHQL";

    /** File Upload Vulnerabilities */
    public static final String FILE_UPLOAD = "FILE_UPLOAD";

    /** Information Disclosure */
    public static final String INFO_DISCLOSURE = "INFO_DISCLOSURE";

    /** WAF Bypass */
    public static final String WAF_BYPASS = "WAF_BYPASS";

    /** Business Logic Flaws */
    public static final String BUSINESS_LOGIC = "BUSINESS_LOGIC";

    /** Mass Assignment */
    public static final String MASS_ASSIGNMENT = "MASS_ASSIGNMENT";

    /** Excessive Data Exposure */
    public static final String EXCESSIVE_DATA = "EXCESSIVE_DATA";

    /** Injection (Generic) */
    public static final String INJECTION = "INJECTION";

    // ======================== Metadata ========================

    private static final Map<String, AttackTypeInfo> REGISTRY;

    static {
        Map<String, AttackTypeInfo> m = new LinkedHashMap<>();

        // OWASP API Security Top 10
        m.put(BOLA, new AttackTypeInfo(
                BOLA, "Broken Object Level Authorization (BOLA/IDOR)",
                "攻击者可以访问不属于自己的资源，通过操纵对象 ID 绕过授权检查",
                "API1:2023", "CRITICAL",
                List.of("MineHistoryIdorTool", "SendRequestTool", "ResponseDiffTool"),
                List.of("bola", "idor", "authorization")
        ));

        m.put(BROKEN_AUTH, new AttackTypeInfo(
                BROKEN_AUTH, "Broken Authentication",
                "认证机制存在缺陷：弱密码策略、JWT 配置错误、凭据泄露、暴力破解无防护",
                "API2:2023", "CRITICAL",
                List.of("AuthBypassTool", "JwtSecurityDetector", "ExtractAuthTool"),
                List.of("auth", "jwt", "brute-force", "credential")
        ));

        m.put(BOPLA, new AttackTypeInfo(
                BOPLA, "Broken Object Property Level Authorization",
                "用户可读取或修改不属于自己的对象属性（过度暴露字段 + 越权写入）",
                "API3:2023", "HIGH",
                List.of("SendRequestTool", "ResponseDiffTool", "BusinessLogicTool"),
                List.of("excessive-data", "mass-assignment", "property-auth")
        ));

        m.put(RESOURCE_CONSUMPTION, new AttackTypeInfo(
                RESOURCE_CONSUMPTION, "Unrestricted Resource Consumption",
                "API 无速率限制/资源配额，可被滥用导致 DoS 或高额账单",
                "API4:2023", "HIGH",
                List.of("HeuristicScanTool", "ActiveProbeTool"),
                List.of("rate-limit", "dos", "resource-exhaustion")
        ));

        m.put(BROKEN_FUNCTION_AUTH, new AttackTypeInfo(
                BROKEN_FUNCTION_AUTH, "Broken Function Level Authorization",
                "低权限用户可访问管理功能或敏感 API 端点",
                "API5:2023", "CRITICAL",
                List.of("AuthBypassTool", "SendRequestTool"),
                List.of("privilege-escalation", "admin-access", "function-auth")
        ));

        m.put(SENSITIVE_BUSINESS_FLOW, new AttackTypeInfo(
                SENSITIVE_BUSINESS_FLOW, "Unrestricted Access to Sensitive Business Flows",
                "自动化滥用敏感业务流程：薅羊毛、刷票、批量注册、垃圾信息",
                "API6:2023", "HIGH",
                List.of("BusinessLogicTool", "SendRequestTool"),
                List.of("abuse", "automation", "business-flow")
        ));

        m.put(SSRF, new AttackTypeInfo(
                SSRF, "Server-Side Request Forgery (SSRF)",
                "诱导服务器发起内部请求，访问内网资源或元数据服务",
                "API7:2023", "HIGH",
                List.of("SsrfOobTool", "CheckOobResultsTool"),
                List.of("ssrf", "oob", "internal-network")
        ));

        m.put(SECURITY_MISCONFIG, new AttackTypeInfo(
                SECURITY_MISCONFIG, "Security Misconfiguration",
                "安全配置错误：调试模式、缺失安全头、CORS 配置不当、信息泄露",
                "API8:2023", "MEDIUM",
                List.of("HeuristicScanTool", "ComponentFingerprintTool"),
                List.of("config", "headers", "cors", "debug", "info-leak")
        ));

        m.put(IMPROPER_INVENTORY, new AttackTypeInfo(
                IMPROPER_INVENTORY, "Improper Inventory Management",
                "未记录/废弃的 API 端点、影子 API、版本不一致",
                "API9:2023", "MEDIUM",
                List.of("BrowserDiscoverTool", "RegisterDiscoveredApisTool", "MapSiblingEndpointsTool"),
                List.of("shadow-api", "deprecated", "inventory")
        ));

        m.put(UNSAFE_CONSUMPTION, new AttackTypeInfo(
                UNSAFE_CONSUMPTION, "Unsafe Consumption of APIs",
                "API 未验证第三方数据、未处理异常响应、信任不可靠来源",
                "API10:2023", "MEDIUM",
                List.of("AnalyzeTrafficTool"),
                List.of("third-party", "data-validation", "trust-boundary")
        ));

        // 传统 Web 漏洞
        m.put(SQL_INJECTION, new AttackTypeInfo(
                SQL_INJECTION, "SQL Injection",
                "通过注入 SQL 代码操纵数据库查询：联合注入、报错注入、盲注",
                "-", "CRITICAL",
                List.of("HeuristicScanTool", "ActiveProbeTool", "BooleanBlindTool", "TimingBlindTool"),
                List.of("sqli", "union", "blind", "time-based")
        ));

        m.put(NOSQL_INJECTION, new AttackTypeInfo(
                NOSQL_INJECTION, "NoSQL Injection",
                "通过注入 MongoDB 操作符（$ne/$gt/$where）绕过认证或操纵查询",
                "-", "HIGH",
                List.of("HeuristicScanTool", "ActiveProbeTool"),
                List.of("nosql", "mongodb", "operator-injection")
        ));

        m.put(XSS, new AttackTypeInfo(
                XSS, "Cross-Site Scripting (XSS)",
                "注入恶意脚本到 Web 页面：反射型、存储型、DOM 型",
                "-", "HIGH",
                List.of("XssReflectionTool", "BrowserDomXssTool"),
                List.of("xss", "reflected", "stored", "dom")
        ));

        m.put(CSRF, new AttackTypeInfo(
                CSRF, "Cross-Site Request Forgery (CSRF)",
                "利用用户已认证的会话执行非预期操作",
                "-", "MEDIUM",
                List.of("HeuristicScanTool"),
                List.of("csrf", "xsrf", "session")
        ));

        m.put(PATH_TRAVERSAL, new AttackTypeInfo(
                PATH_TRAVERSAL, "Path Traversal",
                "通过 ../ 等序列访问任意文件系统路径",
                "-", "HIGH",
                List.of("PathTraversalTool"),
                List.of("lfi", "path", "traversal", "directory")
        ));

        m.put(SSTI, new AttackTypeInfo(
                SSTI, "Server-Side Template Injection (SSTI)",
                "注入模板引擎代码导致远程代码执行",
                "-", "CRITICAL",
                List.of("SstiProbeTool"),
                List.of("ssti", "template", "rce")
        ));

        m.put(XXE, new AttackTypeInfo(
                XXE, "XML External Entity (XXE)",
                "利用 XML 解析器读取文件或发起 SSRF",
                "-", "HIGH",
                List.of("XxeProbeTool"),
                List.of("xxe", "xml", "entity")
        ));

        m.put(DESERIALIZATION, new AttackTypeInfo(
                DESERIALIZATION, "Insecure Deserialization",
                "反序列化不可信数据导致 RCE",
                "-", "CRITICAL",
                List.of("HeuristicScanTool"),
                List.of("deserialization", "java-serialization", "rce")
        ));

        m.put(OPEN_REDIRECT, new AttackTypeInfo(
                OPEN_REDIRECT, "Open Redirect",
                "未验证的重定向参数可被利用进行钓鱼攻击",
                "-", "LOW",
                List.of("HeuristicScanTool"),
                List.of("redirect", "phishing")
        ));

        m.put(REQUEST_SMUGGLING, new AttackTypeInfo(
                REQUEST_SMUGGLING, "HTTP Request Smuggling",
                "利用 CL/TE 不一致走私请求",
                "-", "HIGH",
                List.of("HeuristicScanTool"),
                List.of("smuggling", "cl-te", "te-cl")
        ));

        m.put(GRAPHQL, new AttackTypeInfo(
                GRAPHQL, "GraphQL Specific Issues",
                "Introspection 泄露、深度/复杂度 DoS、批量查询滥用",
                "-", "MEDIUM",
                List.of("HeuristicScanTool"),
                List.of("graphql", "introspection", "depth-limit")
        ));

        m.put(FILE_UPLOAD, new AttackTypeInfo(
                FILE_UPLOAD, "File Upload Vulnerabilities",
                "上传恶意文件（webshell、可执行文件）无扩展名验证",
                "-", "HIGH",
                List.of("HeuristicScanTool"),
                List.of("upload", "webshell", "extension")
        ));

        m.put(INFO_DISCLOSURE, new AttackTypeInfo(
                INFO_DISCLOSURE, "Information Disclosure",
                "泄露敏感信息：错误详情、堆栈跟踪、内网 IP、密钥",
                "-", "MEDIUM",
                List.of("HeuristicScanTool", "SensitiveInfoDetector"),
                List.of("info-leak", "stack-trace", "error-detail")
        ));

        m.put(WAF_BYPASS, new AttackTypeInfo(
                WAF_BYPASS, "WAF Bypass",
                "绕过 Web 应用防火墙的防护规则",
                "-", "HIGH",
                List.of("WafBypassTool", "WafDetector"),
                List.of("waf", "evasion", "encoding")
        ));

        m.put(BUSINESS_LOGIC, new AttackTypeInfo(
                BUSINESS_LOGIC, "Business Logic Flaws",
                "利用业务流程缺陷：竞态条件、价格篡改、状态机违规",
                "-", "HIGH",
                List.of("BusinessLogicTool", "ChainHunterTool"),
                List.of("race-condition", "price-tamper", "state-machine")
        ));

        m.put(MASS_ASSIGNMENT, new AttackTypeInfo(
                MASS_ASSIGNMENT, "Mass Assignment",
                "通过提交未预期字段修改对象属性（如设置 isAdmin=true）",
                "-", "HIGH",
                List.of("SendRequestTool", "ResponseDiffTool"),
                List.of("mass-assignment", "parameter-pollution", "hidden-field")
        ));

        m.put(EXCESSIVE_DATA, new AttackTypeInfo(
                EXCESSIVE_DATA, "Excessive Data Exposure",
                "API 返回过多数据，依赖客户端过滤敏感字段",
                "-", "MEDIUM",
                List.of("AnalyzeTrafficTool", "SensitiveInfoDetector"),
                List.of("data-exposure", "over-fetching", "client-filtering")
        ));

        m.put(INJECTION, new AttackTypeInfo(
                INJECTION, "Injection (Generic)",
                "通用注入漏洞：命令注入、LDAP 注入、XPath 注入等",
                "-", "HIGH",
                List.of("ActiveProbeTool", "GeneratePayloadsTool"),
                List.of("command-injection", "ldap", "xpath")
        ));

        REGISTRY = Collections.unmodifiableMap(m);
    }

    /**
     * 获取所有已注册的攻击类型信息
     */
    public static Map<String, AttackTypeInfo> getAll() {
        return REGISTRY;
    }

    /**
     * 根据 ID 获取攻击类型信息
     */
    public static AttackTypeInfo get(String id) {
        return REGISTRY.get(id);
    }

    /**
     * 获取 OWASP API Top 10 类型（前 10 个）
     */
    public static List<String> getOwaspApiTop10() {
        return List.of(
                BOLA, BROKEN_AUTH, BOPLA, RESOURCE_CONSUMPTION,
                BROKEN_FUNCTION_AUTH, SENSITIVE_BUSINESS_FLOW,
                SSRF, SECURITY_MISCONFIG, IMPROPER_INVENTORY, UNSAFE_CONSUMPTION
        );
    }

    /**
     * 获取所有严重性为 CRITICAL 的攻击类型
     */
    public static List<String> getCriticalTypes() {
        return REGISTRY.values().stream()
                .filter(t -> "CRITICAL".equals(t.severity()))
                .map(AttackTypeInfo::id)
                .toList();
    }

    /**
     * 根据严重性过滤攻击类型
     */
    public static List<String> getBySeverity(String severity) {
        return REGISTRY.values().stream()
                .filter(t -> severity.equals(t.severity()))
                .map(AttackTypeInfo::id)
                .toList();
    }

    /**
     * 根据工具名搜索关联的攻击类型
     */
    public static List<String> getByTool(String toolName) {
        return REGISTRY.values().stream()
                .filter(t -> t.detectors().stream()
                        .anyMatch(d -> d.equalsIgnoreCase(toolName)))
                .map(AttackTypeInfo::id)
                .toList();
    }

    /**
     * 根据 Payload 类别搜索攻击类型
     */
    public static List<String> getByPayloadCategory(String category) {
        return REGISTRY.values().stream()
                .filter(t -> t.payloadCategories().stream()
                        .anyMatch(c -> c.equalsIgnoreCase(category)))
                .map(AttackTypeInfo::id)
                .toList();
    }

    /**
     * 攻击类型元信息
     *
     * @param id                唯一标识符
     * @param name              显示名称
     * @param description       描述
     * @param owaspMapping      OWASP API Top 10 映射（如 "API1:2023"）
     * @param severity          严重性（CRITICAL/HIGH/MEDIUM/LOW）
     * @param detectors         对应检测器/工具列表
     * @param payloadCategories Payload 类别列表
     */
    public record AttackTypeInfo(
            String id,
            String name,
            String description,
            String owaspMapping,
            String severity,
            List<String> detectors,
            List<String> payloadCategories
    ) {}
}
