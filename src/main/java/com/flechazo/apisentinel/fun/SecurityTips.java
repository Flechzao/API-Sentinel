package com.flechazo.apisentinel.fun;

import java.util.*;

/**
 * 安全知识提示 - 发现漏洞时显示相关知识
 */
public class SecurityTips {

    private static final Map<String, List<String>> TIPS = new LinkedHashMap<>();

    static {
        TIPS.put("SQL注入", List.of(
            "OWASP Top 10 #3: SQL 注入是最古老的 Web 漏洞之一，至今仍位居前列。",
            "参数化查询（PreparedStatement）是防御 SQL 注入的黄金标准。",
            "H2/MySQL/PostgreSQL 的错误回显格式不同，可用于指纹识别数据库类型。",
            "布尔盲注通过 true/false 条件差异逐字符提取数据，效率低但难以防御。"
        ));
        TIPS.put("XSS", List.of(
            "OWASP Top 10 #3: XSS 可导致会话劫持、钓鱼和蠕虫传播。",
            "输出编码是关键：HTML 实体编码、JavaScript 编码、URL 编码各有适用场景。",
            "CSP (Content-Security-Policy) 是 XSS 的最后一道防线，但不能替代输入验证。",
            "DOM XSS 不经过服务端，传统 WAF 无法检测。"
        ));
        TIPS.put("IDOR", List.of(
            "OWASP API Top 10 #1: 对象级授权缺失是 API 安全最严重的风险。",
            "IDOR 的防御必须在服务端验证资源归属，前端隐藏不等于安全。",
            "UUID 不能替代授权校验——可猜测性低不等于不可枚举。",
            "水平越权 vs 垂直越权：同级别跨用户 vs 低权限访问高权限功能。"
        ));
        TIPS.put("SSRF", List.of(
            "OWASP Top 10 #10: SSRF 可访问云元数据 (169.254.169.254) 获取临时凭证。",
            "防御 SSRF 需要域名白名单 + 协议限制 + 内网 IP 段过滤三者结合。",
            "DNS Rebinding 可绕过简单的域名白名单检查。"
        ));
        TIPS.put("路径穿越", List.of(
            "路径穿越的经典 payload: ../../etc/passwd (Linux) 或 ..\\..\\windows\\win.ini (Windows)。",
            "防御方法：canonicalize 后校验前缀是否在允许的目录内。",
            "双重编码 (%252e%252e) 和 Unicode 编码可能绕过简单的过滤。"
        ));
        TIPS.put("SSTI", List.of(
            "SSTI 测试: ${7*7} → 49 表示模板被求值。Freemarker/Thymeleaf/Velocity 语法各不同。",
            "Freemarker SSTI 可直接执行系统命令: ${\"freemarker.template.utility.Execute\"?new()(\"id\")}。",
            "防御：用户输入只能作为模板数据，不能作为模板代码执行。"
        ));
        TIPS.put("XXE", List.of(
            "XXE 可读取本地文件、发起 SSRF、甚至执行拒绝服务攻击 (Billion Laughs)。",
            "防御：禁用 DTD 和外部实体 (disallow-doctype-decl, external-general-entities=false)。",
            "Java 中 DocumentBuilderFactory、SAXParser、XMLReader 都需要单独配置安全选项。"
        ));
        TIPS.put("命令注入", List.of(
            "命令注入的 payload: ;cat /etc/passwd 或 |whoami 或 $(id) 或 `id`。",
            "防御：避免调用系统命令，必须用时使用参数数组而非字符串拼接。",
            "即使过滤了常见分隔符，换行符 (\\n) 和空字节 (\\0) 仍可能绕过。"
        ));
        TIPS.put("认证绕过", List.of(
            "常见绕过方式：JWT alg:none、Cookie 伪造、HTTP 方法覆盖、路径遍历 (/admin/../api)。",
            "防御：服务端必须独立验证每个请求的身份，不能信任客户端传递的角色信息。",
            "OAuth 实现中 redirect_uri 校验不严可导致授权码窃取。"
        ));
        TIPS.put("CORS", List.of(
            "CORS 配置错误 + Allow-Credentials: true = 任意站点可读取已登录用户数据。",
            "Origin 反射 (将请求的 Origin 原样返回) 等同于 Access-Control-Allow-Origin: *。",
            "null Origin (来自 file:// 或沙箱 iframe) 也需要在白名单中排除。"
        ));
        TIPS.put("业务逻辑", List.of(
            "竞态条件 (TOCTOU): 检查和操作之间的时间窗口可被并发请求利用。",
            "价格篡改、优惠券重放、负数数量是最常见的业务逻辑漏洞。",
            "防御：关键操作使用数据库原子操作 (UPDATE ... WHERE balance >= amount)。"
        ));
        TIPS.put("信息泄露", List.of(
            "堆栈跟踪泄露可暴露框架版本、类名和内部路径，帮助攻击者精准构造 payload。",
            "生产环境应设置 server.error.include-stacktrace=never。",
            ".git/、.env、actuator 端点是最常见的信息泄露来源。"
        ));
    }

    private static final Random random = new Random();

    public static String getTip(String vulnType) {
        if (vulnType == null || vulnType.isBlank()) return null;
        for (Map.Entry<String, List<String>> entry : TIPS.entrySet()) {
            if (vulnType.contains(entry.getKey()) || entry.getKey().contains(vulnType)) {
                List<String> tips = entry.getValue();
                return tips.get(random.nextInt(tips.size()));
            }
        }
        return null;
    }

    public static String getRandomTip() {
        List<List<String>> all = new ArrayList<>(TIPS.values());
        List<String> tips = all.get(random.nextInt(all.size()));
        return tips.get(random.nextInt(tips.size()));
    }
}
