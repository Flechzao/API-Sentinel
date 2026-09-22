package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.logging.LeveledLogger;

import com.flechazo.apisentinel.util.HttpMessageUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Local heuristic detection for common security issues.
 * Zero AI cost, millisecond response time.
 * Runs alongside AI analysis to catch obvious patterns that don't need LLM.
 */
/** 启发式检测器——被动检测 13 类正则签名（SQL错误/堆栈/安全头/CORS/CSRF/请求走私等）。 */
public class HeuristicDetector {

    private final LeveledLogger logger;

    // --- SQL Error patterns ---
    private static final Pattern[] SQL_ERROR_PATTERNS = {
        Pattern.compile("(?i)(SQL syntax.*?MySQL|Warning.*?\\Wmysqli?_|MySqlException|com\\.mysql\\.jdbc)"),
        Pattern.compile("(?i)(PostgreSQL.*?ERROR|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s+syntax error at)"),
        Pattern.compile("(?i)(ORA-\\d{5}|oracle\\.jdbc\\.driver|PLS-\\d{5}|TNS-\\d{5})"),
        Pattern.compile("(?i)(\\[Microsoft\\]\\[ODBC SQL Server|SQLServer JDBC Driver|com\\.microsoft\\.sqlserver)"),
        Pattern.compile("(?i)(SQLite3?::Exception|SQLSTATE\\[\\w+\\]|near \".*?\": syntax error)"),
        Pattern.compile("(?i)(JDBC[a-zA-Z]*Exception|java\\.sql\\.SQLException|Hibernate[a-zA-Z]*Exception)")
    };

    // --- Stack trace patterns ---
    private static final Pattern STACK_TRACE = Pattern.compile(
        "(?i)(Traceback \\(most recent call|at [a-zA-Z0-9_.]+\\([a-zA-Z0-9_]+\\.java:\\d+\\)|" +
        "File \"[^\"]+\", line \\d+|System\\.NullReferenceException|" +
        "Exception in thread|java\\.lang\\.(NullPointerException|ClassCastException)|" +
        "RuntimeError|TypeError|ValueError|AttributeError)"
    );

    // --- Server info disclosure ---
    private static final Pattern SERVER_INFO = Pattern.compile(
        "(?i)(X-Powered-By:\\s*(PHP|ASP\\.NET|Express|JSP)|" +
        "Server:\\s*(Apache|nginx|IIS|Tomcat|Jetty|Undertow)/[\\d.]+)"
    );

    // --- Debug mode indicators ---
    private static final Pattern DEBUG_MODE = Pattern.compile(
        "(?i)(\"debug\"\\s*:\\s*true|DEBUG\\s*=\\s*True|DJANGO_DEBUG|" +
        "laravel_session|Whitelabel Error Page|X-Debug-Token)"
    );

    // --- Private IP leak (word-boundary anchored to avoid matching version
    // strings like "version":"10.2.3.4" or build numbers). Each branch spells
    // out its own full 4-octet suffix — sharing a single ".d{1,3}.d{1,3}"
    // tail across all three (as an earlier version of this pattern did) only
    // gives the bare "10" branch 3 octets total instead of 4, truncating
    // real IPs like 10.1.20.5 to "10.1.20". ---
    private static final Pattern PRIVATE_IP = Pattern.compile(
        "(?<!\\d)(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" +
        "|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}" +
        "|192\\.168\\.\\d{1,3}\\.\\d{1,3})(?!\\d)"
    );

    // --- Missing security headers ---
    private static final String[] SECURITY_HEADERS = {
        "strict-transport-security",   // HSTS
        "content-security-policy",     // CSP
        "x-frame-options",             // clickjacking
        "x-content-type-options",      // MIME sniffing
        "referrer-policy"
    };

    // --- Dangerous file upload ---
    private static final Pattern DANGEROUS_UPLOAD = Pattern.compile(
        "(?i)filename=[\"']?[^\"']*\\.(jsp|jspx|php|phtml|asp|aspx|exe|sh|bat|cmd|war|jar)[\"'\\s;]"
    );

    // --- Deserialization ---
    private static final String JAVA_SERIALIZED_MAGIC = "aced0005";
    private static final Pattern VIEWSTATE = Pattern.compile("__VIEWSTATE[^=]*=([A-Za-z0-9+/=]{50,})");

    public HeuristicDetector(LeveledLogger logger) {
        this.logger = logger;
    }

    /**
     * Detect heuristic security issues from HTTP request/response.
     * Returns a list of findings.
     */
    public List<HeuristicFinding> detect(String method, String url,
                                          String rawRequest, String rawResponse,
                                          int statusCode) {
        List<HeuristicFinding> findings = new ArrayList<>();

        if (rawResponse != null && !rawResponse.isEmpty()) {
            detectSqlErrors(rawResponse, findings);
            detectStackTraces(rawResponse, findings);
            detectServerInfoLeak(rawResponse, findings);
            detectDebugMode(rawResponse, findings);
            detectPrivateIpLeak(rawResponse, findings);
            detectCorsMisconfiguration(rawRequest, rawResponse, findings);
            detectMissingSecurityHeaders(rawResponse, statusCode, findings);
            detectOpenRedirect(method, url, rawRequest, statusCode, findings);
            findings.addAll(JwtSecurityDetector.detectJwtIssues(rawResponse));
        }

        if (rawRequest != null && !rawRequest.isEmpty()) {
            detectCsrfMissing(method, rawRequest, findings);
            detectRequestSmuggling(rawRequest, findings);
            detectDangerousUpload(rawRequest, statusCode, findings);
            detectDeserializationRisk(rawRequest, findings);
            detectNoSqlOperators(rawRequest, findings);
            detectSensitiveParamsInUrl(rawRequest, findings);
            detectGraphQL(url, rawRequest, rawResponse, findings);
            detectMassAssignment(method, rawRequest, rawResponse, statusCode, findings);
            detectExcessiveDataExposure(rawResponse, url, findings);
        }

        if (!findings.isEmpty()) {
            // Log path only (not full URL) to avoid leaking internal hostnames.
            // Debug level — the findings are stored on the ApiEntry via
            // addPassiveFindingIfAbsent (which deduplicates), so the log
            // is just diagnostic. RPC gateway patterns send many requests
            // to the same URL, which would spam the output at info level.
            String logPath = com.flechazo.apisentinel.util.UrlUtils.extractPath(url);
            logger.debug("[Heuristic] %s %s: 检测到 %d 个问题", method, logPath, findings.size());
        }

        return findings;
    }

    private void detectSqlErrors(String response, List<HeuristicFinding> findings) {
        for (Pattern p : SQL_ERROR_PATTERNS) {
            var m = p.matcher(response);
            if (m.find()) {
                findings.add(new HeuristicFinding(
                    "MEDIUM", "信息泄露", "数据库错误信息泄露",
                    "响应中包含数据库错误信息: " + truncate(m.group(), 100),
                    "隐藏详细错误信息，使用通用错误页面"
                ));
                break; // one SQL error finding is enough
            }
        }
    }

    private void detectStackTraces(String response, List<HeuristicFinding> findings) {
        var m = STACK_TRACE.matcher(response);
        if (m.find()) {
            findings.add(new HeuristicFinding(
                "LOW", "信息泄露", "堆栈跟踪泄露",
                "响应中包含堆栈跟踪信息: " + truncate(m.group(), 100),
                "在生产环境关闭 debug 模式，使用通用错误页面"
            ));
        }
    }

    private void detectServerInfoLeak(String response, List<HeuristicFinding> findings) {
        var m = SERVER_INFO.matcher(response);
        if (m.find()) {
            findings.add(new HeuristicFinding(
                "INFO", "信息泄露", "服务器版本信息泄露",
                "响应头中暴露了服务器/框架版本: " + truncate(m.group(), 80),
                "隐藏 Server / X-Powered-By 响应头"
            ));
        }
    }

    private void detectDebugMode(String response, List<HeuristicFinding> findings) {
        var m = DEBUG_MODE.matcher(response);
        if (m.find()) {
            findings.add(new HeuristicFinding(
                "MEDIUM", "配置错误", "调试模式开启",
                "响应中检测到调试模式标记: " + truncate(m.group(), 80),
                "在生产环境关闭 debug 模式"
            ));
        }
    }

    private void detectPrivateIpLeak(String response, List<HeuristicFinding> findings) {
        var m = PRIVATE_IP.matcher(response);
        if (m.find()) {
            findings.add(new HeuristicFinding(
                "LOW", "信息泄露", "内网 IP 地址泄露",
                "响应中包含内网 IP: " + m.group(),
                "避免在响应中暴露内网 IP 地址"
            ));
        }
    }

    /**
     * Detect missing security response headers. Only meaningful for HTML/2xx
     * responses (APIs returning JSON to XHR/fetch clients usually don't set
     * browser security headers, so we scope to HTML-ish responses to limit noise).
     */
    private void detectMissingSecurityHeaders(String rawResponse, int statusCode, List<HeuristicFinding> findings) {
        if (rawResponse == null || rawResponse.isEmpty()) return;
        // Only flag on successful HTML-ish responses; skip JSON APIs and errors
        String lower = rawResponse.toLowerCase();
        boolean isHtml = lower.contains("content-type: text/html") || lower.contains("<!doctype html") || lower.contains("<html");
        if (!isHtml || statusCode < 200 || statusCode >= 300) return;

        String headerBlock = lower.substring(0, Math.min(lower.length(),
                lower.indexOf("\r\n\r\n") >= 0 ? lower.indexOf("\r\n\r\n") : lower.length()));

        for (String header : SECURITY_HEADERS) {
            if (!headerBlock.contains(header + ":")) {
                findings.add(new HeuristicFinding(
                    "LOW", "配置错误", "缺失安全响应头: " + header,
                    "响应未设置 " + header + " 头",
                    "为 HTML 响应设置 " + header + " 等安全响应头"
                ));
            }
        }
    }

    private void detectCsrfMissing(String method, String rawRequest, List<HeuristicFinding> findings) {
        // Only check state-changing methods
        if (!method.equalsIgnoreCase("POST") && !method.equalsIgnoreCase("PUT")
                && !method.equalsIgnoreCase("DELETE") && !method.equalsIgnoreCase("PATCH")) {
            return;
        }

        String lowerReq = rawRequest.toLowerCase();
        // Check if request uses cookie-based auth
        if (!lowerReq.contains("cookie:")) return;

        // Check for CSRF token
        boolean hasCsrfToken = lowerReq.contains("csrf") || lowerReq.contains("xsrf")
                || lowerReq.contains("x-csrf") || lowerReq.contains("_token")
                || lowerReq.contains("authenticity_token");

        if (!hasCsrfToken) {
            findings.add(new HeuristicFinding(
                "LOW", "CSRF", "状态变更接口缺少 CSRF 防护",
                method + " 请求使用 Cookie 认证但未携带 CSRF Token",
                "为状态变更接口添加 CSRF Token 验证"
            ));
        }
    }

    private void detectRequestSmuggling(String rawRequest, List<HeuristicFinding> findings) {
        String lowerReq = rawRequest.toLowerCase();
        boolean hasCL = lowerReq.contains("content-length:");
        boolean hasTE = lowerReq.contains("transfer-encoding:");

        if (hasCL && hasTE) {
            findings.add(new HeuristicFinding(
                "HIGH", "请求走私", "Content-Length 与 Transfer-Encoding 共存",
                "请求同时包含 Content-Length 和 Transfer-Encoding 头，可能导致请求走私",
                "确保代理和后端对 CL/TE 的处理一致"
            ));
        }

        // Check for duplicate Content-Length
        int clCount = 0;
        for (String line : rawRequest.split("\r?\n")) {
            if (line.toLowerCase().startsWith("content-length:")) clCount++;
        }
        if (clCount > 1) {
            findings.add(new HeuristicFinding(
                "HIGH", "请求走私", "重复的 Content-Length 头",
                "请求包含 " + clCount + " 个 Content-Length 头",
                "确保 HTTP 请求只包含一个 Content-Length 头"
            ));
        }
    }

    private void detectDangerousUpload(String rawRequest, int statusCode, List<HeuristicFinding> findings) {
        if (!rawRequest.toLowerCase().contains("multipart/form-data")) return;

        var m = DANGEROUS_UPLOAD.matcher(rawRequest);
        if (m.find() && statusCode >= 200 && statusCode < 300) {
            findings.add(new HeuristicFinding(
                "HIGH", "文件上传", "危险文件扩展名上传成功",
                "上传了危险扩展名文件且服务器返回成功: " + truncate(m.group(), 80),
                "限制上传文件扩展名白名单，避免允许可执行文件"
            ));
        }
    }

    private void detectDeserializationRisk(String rawRequest, List<HeuristicFinding> findings) {
        // Check body portion for Java serialized objects
        int bodyStart = rawRequest.indexOf("\r\n\r\n");
        if (bodyStart < 0) bodyStart = rawRequest.indexOf("\n\n");
        if (bodyStart >= 0) {
            String body = rawRequest.substring(bodyStart);
            if (body.length() >= 4) {
                StringBuilder hex = new StringBuilder();
                for (int i = 0; i < Math.min(body.length(), 20); i++) {
                    hex.append(String.format("%02x", (int) body.charAt(i)));
                }
                if (hex.toString().contains(JAVA_SERIALIZED_MAGIC)) {
                    findings.add(new HeuristicFinding(
                        "HIGH", "反序列化", "检测到 Java 序列化数据",
                        "请求体包含 Java 序列化魔术字节 (0xaced0005)",
                        "避免使用原生 Java 序列化，改用 JSON 等安全格式"
                    ));
                }
            }
        }

        // Check for .NET ViewState
        var m = VIEWSTATE.matcher(rawRequest);
        if (m.find()) {
            findings.add(new HeuristicFinding(
                "MEDIUM", "反序列化", "检测到 .NET ViewState",
                "请求包含 ViewState 参数，可能存在反序列化风险",
                "启用 ViewState MAC 验证，考虑加密 ViewState"
            ));
        }
    }

    private void detectCorsMisconfiguration(String rawRequest, String rawResponse, List<HeuristicFinding> findings) {
        String lowerResp = rawResponse.toLowerCase();

        String acao = extractHeaderValue(lowerResp, "access-control-allow-origin");
        if (acao == null) return;

        boolean allowCredentials = "true".equalsIgnoreCase(
                extractHeaderValue(lowerResp, "access-control-allow-credentials"));

        if ("*".equals(acao.trim()) && allowCredentials) {
            findings.add(new HeuristicFinding(
                "MEDIUM", "CORS 配置错误", "通配符 Origin 配合凭据共享",
                "Access-Control-Allow-Origin: * 与 Access-Control-Allow-Credentials: true 同时存在。"
                + "注：现代浏览器会忽略此组合（规范不允许 * 与凭据同时使用），实际不可利用，但属配置错误。",
                "指定明确的 Origin 白名单，避免使用通配符配合凭据"
            ));
            return;
        }

        if (rawRequest != null) {
            String requestOrigin = extractHeaderValue(rawRequest.toLowerCase(), "origin");
            if (requestOrigin != null && !requestOrigin.isBlank()
                    && acao.trim().equalsIgnoreCase(requestOrigin.trim())
                    && !"*".equals(acao.trim())) {
                findings.add(new HeuristicFinding(
                    allowCredentials ? "HIGH" : "MEDIUM",
                    "CORS 配置错误", "Origin 反射",
                    "Access-Control-Allow-Origin 直接反射请求的 Origin: " + requestOrigin.trim()
                        + (allowCredentials ? " (且允许凭据)" : ""),
                    "不要直接反射请求的 Origin，使用白名单验证"
                ));
            }
        }

        if (!"*".equals(acao.trim()) && acao.trim().equals("null") && allowCredentials) {
            findings.add(new HeuristicFinding(
                "MEDIUM", "CORS 配置错误", "允许 null Origin",
                "Access-Control-Allow-Origin: null 配合凭据共享，可被 iframe sandbox 利用",
                "不要信任 null Origin"
            ));
        }
    }

    private static String extractHeaderValue(String rawHttp, String headerName) {
        String prefix = headerName + ":";
        for (String line : rawHttp.split("\r?\n")) {
            if (line.toLowerCase().startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    // ======================== New detection patterns ========================

    private static final Pattern NOSQL_OPERATOR = Pattern.compile(
            "(?i)\\$(ne|gt|gte|lt|lte|regex|where|in|nin|or|and|mod|size|exists|type)\\s*[\\(:]");
    private static final Pattern GRAPHQL_PATTERN = Pattern.compile(
            "(?i)(query\\s*\\{|mutation\\s*\\{|subscription\\s*\\{|__schema|__typename|application/graphql)");
    private static final Pattern SENSITIVE_PARAM_IN_URL = Pattern.compile(
            "(?i)[?&](password|passwd|pwd|secret|token|apikey|api_key|access_token|refresh_token|private_key)\\s*=");

    private void detectNoSqlOperators(String rawRequest, List<HeuristicFinding> findings) {
        String body = HttpMessageUtils.bodyOf(rawRequest);
        if (body == null || body.isEmpty()) return;
        var m = NOSQL_OPERATOR.matcher(body);
        if (m.find()) {
            findings.add(new HeuristicFinding(
                    "MEDIUM", "NoSQL注入", "请求体含 NoSQL 查询操作符",
                    "发现 $" + m.group(1) + " 操作符：未经过滤的查询操作符可绕过认证",
                    "过滤请求体中以 $ 开头的字段，或使用白名单校验查询条件"
            ));
        }
    }

    private void detectSensitiveParamsInUrl(String rawRequest, List<HeuristicFinding> findings) {
        String reqLine = rawRequest.split("\r?\n")[0];
        var m = SENSITIVE_PARAM_IN_URL.matcher(reqLine);
        if (m.find()) {
            findings.add(new HeuristicFinding(
                    "MEDIUM", "信息泄露", "敏感参数出现在 URL 中",
                    "参数 " + m.group(1) + " 通过 URL 传输，可能被日志/Referer 泄露",
                    "将敏感参数移至 POST body，使用 HTTPS 传输"
            ));
        }
    }

    private void detectGraphQL(String url, String rawRequest, String rawResponse,
                                List<HeuristicFinding> findings) {
        // Check URL path for /graphql
        if (url != null && url.toLowerCase().contains("/graphql")) {
            findings.add(new HeuristicFinding(
                    "INFO", "GraphQL", "检测到 GraphQL 端点",
                    "URL 路径包含 /graphql",
                    "检查是否启用了 introspection 查询、是否有深度/复杂度限制"
            ));
        }
        // Check request body for GraphQL query/mutation
        String body = rawRequest != null ? HttpMessageUtils.bodyOf(rawRequest) : null;
        if (body != null && !body.isEmpty()) {
            var m = GRAPHQL_PATTERN.matcher(body);
            if (m.find()) {
                findings.add(new HeuristicFinding(
                        "INFO", "GraphQL", "请求体含 GraphQL 查询",
                        "匹配到 " + m.group(),
                        "检查 introspection 是否禁用、查询深度是否有限制"
                ));
            }
        }
        // Check response for GraphQL introspection results
        if (rawResponse != null && rawResponse.contains("__schema")) {
            findings.add(new HeuristicFinding(
                    "MEDIUM", "GraphQL", "GraphQL introspection 已启用",
                    "响应包含 __schema，允许结构内省查询",
                    "生产环境禁用 introspection"
            ));
        }
    }

    private void detectOpenRedirect(String method, String url, String rawRequest,
                                     int statusCode, List<HeuristicFinding> findings) {
        // Open redirect: 3xx status + redirect-like parameter in URL
        if (statusCode >= 300 && statusCode < 400) {
            String reqLine = rawRequest != null ? rawRequest.split("\r?\n")[0] : "";
            if (reqLine.matches("(?i).*(redirect|next|url|return|callback|goto|continue)\\s*=")) {
                findings.add(new HeuristicFinding(
                        "MEDIUM", "开放重定向", "3xx 响应 + URL 含重定向参数",
                        statusCode + " 重定向 + 请求含 redirect/next/url 参数",
                        "对重定向目标做白名单校验，不直接使用用户提供的 URL"
                ));
            }
        }
    }

    // ======================== Mass Assignment ========================

    /** 常见的 Mass Assignment 危险字段 */
    private static final Pattern MASS_ASSIGNMENT_FIELDS = Pattern.compile(
            "(?i)[\"'](" +
            "is_?admin|is_?root|is_?superuser|is_?privileged|role|roles|permission|permissions|" +
            "is_?active|is_?verified|is_?enabled|is_?banned|is_?locked|" +
            "balance|credit|price|amount|discount|cost|" +
            "created_?at|updated_?at|deleted_?at|is_?deleted|" +
            "owner_?id|user_?id|tenant_?id" +
            ")[\"']\\s*[:=]");

    private void detectMassAssignment(String method, String rawRequest, String rawResponse,
                                       int statusCode, List<HeuristicFinding> findings) {
        // Only check write operations
        if (!method.equalsIgnoreCase("POST") && !method.equalsIgnoreCase("PUT")
                && !method.equalsIgnoreCase("PATCH")) {
            return;
        }

        String body = HttpMessageUtils.bodyOf(rawRequest);
        if (body == null || body.isEmpty()) return;

        // Check for suspicious field names in request body
        var m = MASS_ASSIGNMENT_FIELDS.matcher(body);
        if (m.find() && statusCode >= 200 && statusCode < 300) {
            findings.add(new HeuristicFinding(
                    "HIGH", "Mass Assignment",
                    "请求体包含可能被直接赋值的敏感字段: " + m.group(1),
                    "写操作请求体发现 " + m.group(1) + " 字段且服务器返回成功（" + statusCode + "），"
                    + "可能存在批量赋值漏洞。攻击者可提交未预期字段修改对象属性。",
                    "使用白名单只允许客户端可修改的字段，使用 DTO 模式隔离输入与内部模型"
            ));
        }
    }

    // ======================== Excessive Data Exposure ========================

    /** 敏感字段模式（响应中不应出现的字段） */
    private static final Pattern SENSITIVE_RESPONSE_FIELDS = Pattern.compile(
            "(?i)[\"'](" +
            "password|passwd|pwd|secret|api_?key|apikey|access_?token|refresh_?token|" +
            "private_?key|encryption_?key|session_?id|auth_?token|" +
            "ssn|social_?security|credit_?card|card_?number|cvv|cvv2|" +
            "phone|mobile|email|address|date_?of_?birth|dob" +
            ")[\"']\\s*:");

    private void detectExcessiveDataExposure(String rawResponse, String url,
                                              List<HeuristicFinding> findings) {
        if (rawResponse == null || rawResponse.isEmpty()) return;

        // Only check JSON responses
        String lowerResp = rawResponse.toLowerCase();
        if (!lowerResp.contains("content-type: application/json")) return;

        int bodyStart = rawResponse.indexOf("\r\n\r\n");
        if (bodyStart < 0) bodyStart = rawResponse.indexOf("\n\n");
        if (bodyStart < 0) return;

        String body = rawResponse.substring(bodyStart);

        // Check for sensitive fields in response
        var m = SENSITIVE_RESPONSE_FIELDS.matcher(body);
        List<String> sensitiveFields = new ArrayList<>();
        while (m.find() && sensitiveFields.size() < 5) {
            sensitiveFields.add(m.group(1));
        }

        if (!sensitiveFields.isEmpty()) {
            String path = url != null ? com.flechazo.apisentinel.util.UrlUtils.extractPath(url) : "unknown";
            findings.add(new HeuristicFinding(
                    "MEDIUM", "Excessive Data Exposure",
                    "API 响应包含 " + sensitiveFields.size() + " 个敏感字段",
                    "路径 " + path + " 的响应中发现敏感字段: "
                    + String.join(", ", sensitiveFields) + "。"
                    + "API 返回了过多数据，客户端可能依赖这些字段进行过滤。",
                    "使用 DTO 模式只返回必要字段，避免直接序列化内部模型。"
                    + "特别避免返回密码、密钥、Token 等凭证类字段"
            ));
        }

        // Also check for excessively large responses (potential data leak indicator)
        if (body.length() > 50000) {
            String path = url != null ? com.flechazo.apisentinel.util.UrlUtils.extractPath(url) : "unknown";
            findings.add(new HeuristicFinding(
                    "LOW", "Excessive Data Exposure",
                    "API 响应体过大（" + (body.length() / 1024) + " KB）",
                    "路径 " + path + " 返回了 " + (body.length() / 1024) + " KB 的响应体，"
                    + "可能包含过多数据。检查是否有分页或数据过滤机制。",
                    "实现分页查询，限制单次返回数据量。使用字段过滤只返回必要字段"
            ));
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
    }

    /**
     * A single heuristic finding.
     */
    public record HeuristicFinding(
        String risk,       // HIGH, MEDIUM, LOW, INFO
        String category,   // e.g. "信息泄露", "CSRF", "请求走私"
        String title,      // Short title
        String evidence,   // Evidence found
        String remediation // Fix suggestion
    ) {}
}
