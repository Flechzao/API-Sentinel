package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.util.HttpMessageUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Passive component fingerprinting: identifies backend frameworks/libraries/
 * admin endpoints from response headers, body markers and the request URL —
 * zero requests sent. Complements (does not duplicate) HeuristicDetector,
 * which already covers Server-version / X-Powered-By / Whitelabel / Django
 * debug / laravel_session; this class focuses on the signals it lacks and
 * attaches an associated-vuln hint + risk level to each component.
 */
public final class ComponentFingerprinter {

    /** One fingerprinted component with its associated-vuln hint. */
    public record ComponentInfo(
            String name,        // "Fastjson"
            String category,    // "JSON 库" / "框架" / "中间件" / "管理端点"
            String vuln,        // associated vulnerability hint
            String risk,        // HIGH / MEDIUM / LOW / INFO
            String evidence     // what matched
    ) {}

    private record Rule(String name, String category, String vuln, String risk,
                        Pattern pattern, int where) {}
    // where: 1 = headers, 2 = body, 3 = URL path

    private static final int HEADERS = 1, BODY = 2, PATH = 3;

    private static final List<Rule> RULES = new ArrayList<>();
    static {
        // ── Response-header fingerprints ──
        add("ASP.NET", "框架", "详细错误页/ViewState 攻击面", "INFO",
                "(?i)^X-AspNet-Version:", HEADERS);
        add("ASP.NET MVC", "框架", "详细错误页/ViewState 攻击面", "INFO",
                "(?i)^X-AspNetMvc-Version:", HEADERS);
        add("Rails", "框架", "参数污染/反序列化历史漏洞", "INFO",
                "(?i)^X-Runtime:", HEADERS);
        add("Spring Boot", "框架", "Actuator/spEL 攻击面", "INFO",
                "(?i)^X-Application-Context:", HEADERS);
        add("Java Servlet", "运行时", "反序列化攻击面", "INFO",
                "(?i)^Set-Cookie:.*JSESSIONID", HEADERS);
        add("PHP", "运行时", "类型混淆/反序列化攻击面", "INFO",
                "(?i)^Set-Cookie:.*PHPSESSID", HEADERS);
        add("Node/Express", "运行时", "原型链污染攻击面", "INFO",
                "(?i)^Set-Cookie:.*connect\\.sid", HEADERS);
        add("ASP.NET Session", "运行时", "ViewState 攻击面", "INFO",
                "(?i)^Set-Cookie:.*ASP\\.NET_SessionId", HEADERS);

        // ── Response-body fingerprints ──
        add("Fastjson", "JSON 库", "反序列化 RCE（autoType）", "HIGH",
                "(?i)com\\.alibaba\\.fastjson|fastjson[^a-z]", BODY);
        add("Log4j", "日志库", "Log4Shell JNDI 注入（CRITICAL 级）", "HIGH",
                "(?i)log4j|org\\.apache\\.logging\\.log4j", BODY);
        add("Shiro", "认证框架", "RememberMe 反序列化 RCE", "HIGH",
                "(?i)rememberMe=deleteMe|shiro", HEADERS);
        add("Next.js", "前端框架", "SSRF/中间件绕过历史漏洞", "LOW",
                "__NEXT_DATA__", BODY);
        add("Nuxt", "前端框架", "历史 XSS/SSRF", "LOW",
                "__NUXT__|window\\.__NUXT__", BODY);
        add("Angular", "前端框架", "模板沙箱逃逸历史漏洞", "LOW",
                "ng-version|angular[.-][0-9]", BODY);
        add("WordPress", "CMS", "插件漏洞/REST 信息泄露", "MEDIUM",
                "wp-content/|wp-includes/", BODY);
        add("Flask Debug", "框架调试", "Werkzeug 调试控制台 RCE", "HIGH",
                "Werkzeug Debugger|console\\.debug|__debugger__", BODY);
        add("ASP.NET 详细错误", "框架", "堆栈/配置信息泄露", "MEDIUM",
                "Server Error in '/' Application|yellow.*screen|<b> Stack Trace:", BODY);
        add("Rails 错误页", "框架", "参数/堆栈信息泄露", "LOW",
                "Action Controller: Exception caught|actionpack", BODY);

        // ── URL-path fingerprints (match the captured request's own path) ──
        add("Nacos", "注册中心", "默认口令/认证绕过/反序列化", "HIGH",
                "(?i)/nacos(/|$)", PATH);
        add("Druid 监控", "连接池监控", "未授权监控页/session 泄露", "MEDIUM",
                "(?i)/druid(/|/index\\.html)", PATH);
        add("Spring Actuator heapdump", "调试端点", "堆转储泄露凭证", "HIGH",
                "(?i)/actuator/heapdump", PATH);
        add("Spring Actuator", "调试端点", "env/configprops 信息泄露", "MEDIUM",
                "(?i)/actuator(/|$)", PATH);
        add("Jolokia", "JMX 桥接", "JMX RCE", "HIGH",
                "(?i)/jolokia(/|$)", PATH);
        add("Swagger 文档", "API 文档", "接口面暴露", "LOW",
                "(?i)/swagger-ui|/swagger\\.json|/swagger-resources", PATH);
        add("OpenAPI 文档", "API 文档", "接口面暴露", "LOW",
                "(?i)/v[23]/api-docs|/api-docs", PATH);
        add("JBoss JMX Console", "管理端点", "未授权部署 RCE", "HIGH",
                "(?i)/jmx-console(/|$)|/web-console(/|$)", PATH);
        add("phpMyAdmin", "数据库管理", "弱口令/历史 RCE", "MEDIUM",
                "(?i)/phpmyadmin(/|$)", PATH);
        add("XXL-Job", "任务调度", "执行器未授权 RCE", "HIGH",
                "(?i)/xxl-job(-admin)?(/|$)", PATH);
    }

    private static void add(String name, String category, String vuln, String risk,
                            String regex, int where) {
        // Header rules use ^ line anchors → need MULTILINE (header section is
        // multi-line and the status line is stripped before matching).
        RULES.add(new Rule(name, category, vuln, risk,
                Pattern.compile(regex, where == HEADERS ? Pattern.MULTILINE : 0), where));
    }

    private ComponentFingerprinter() {}

    /**
     * Fingerprint components from a captured response (+ the request URL).
     * Pure/passive — sends nothing. Results are de-duplicated by name and
     * sorted HIGH → LOW.
     *
     * @param rawResponse raw HTTP response text (headers + body)
     * @param url         the captured request URL or path (for path rules)
     */
    public static List<ComponentInfo> fingerprint(String rawResponse, String url) {
        String section = rawResponse == null ? "" : HttpMessageUtils.headerSection(rawResponse);
        // Drop the status line so ^-anchored header rules match real headers.
        String[] headerLines = section.split("\r?\n");
        String headers = headerLines.length > 1
                ? String.join("\n", java.util.Arrays.copyOfRange(headerLines, 1, headerLines.length))
                : "";
        String body = rawResponse == null ? "" : HttpMessageUtils.bodyOf(rawResponse);
        // Cap body scanning to keep it cheap on large responses.
        if (body.length() > 20000) body = body.substring(0, 20000);
        String path = url == null ? "" : url.toLowerCase(Locale.ROOT);

        List<ComponentInfo> out = new ArrayList<>();
        List<String> seen = new ArrayList<>();
        for (Rule r : RULES) {
            String target = switch (r.where()) {
                case HEADERS -> headers;
                case BODY -> body;
                default -> path;
            };
            if (target.isEmpty()) continue;
            if (r.pattern().matcher(target).find() && !seen.contains(r.name())) {
                seen.add(r.name());
                out.add(new ComponentInfo(r.name(), r.category(), r.vuln(), r.risk(),
                        evidenceFor(r, target)));
            }
        }
        out.sort(Comparator.comparingInt(ComponentFingerprinter::riskRank));
        return out;
    }

    private static String evidenceFor(Rule r, String target) {
        // Short evidence snippet: the first matched line (trimmed).
        for (String line : target.split("\r?\n")) {
            if (r.pattern().matcher(line).find()) {
                String l = line.trim();
                return l.length() > 120 ? l.substring(0, 120) + "…" : l;
            }
        }
        return r.name() + " 特征命中";
    }

    private static int riskRank(ComponentInfo c) {
        return switch (c.risk()) {
            case "HIGH" -> 0;
            case "MEDIUM" -> 1;
            case "LOW" -> 2;
            default -> 3;
        };
    }
}
