package com.flechazo.apisentinel.ai.prompt;

import java.util.Set;

/**
 * Single source of truth for "what counts as an informational-only finding
 * that must NOT be promoted to a confirmed/suspected vuln" — distilled from
 * bughunter's triage-validation NEVER-SUBMIT list / kill signals, adapted to
 * this project's internal-API-testing context.
 *
 * Three consumers, all reading from THIS file so they can't drift apart
 * (the second-round Agent/Pipeline verdict drift was caused by two copies of
 * the rules living in two places):
 *  - {@link FinalVerdictPrompt} and {@code AgentLoop.buildSystemPrompt()} inject
 *    {@link #NEVER_CONFIRM_PROMPT_TEXT} / {@link #AGENT_CONDENSED_RULES} into
 *    their system prompts (LLM-side guardrail).
 *  - {@link com.flechazo.apisentinel.ai.pipeline.VerdictValidator} consults
 *    {@link #isInformationalType(String)} / {@link #hasChainEvidence(String)}
 *    as a programmatic backstop for when the LLM ignores the prompt (demotes
 *    instead of deleting, and notes it in the summary).
 *
 * Content is public, well-known pentest knowledge (no proprietary signatures).
 * Distilled from shuvonsec/claude-bug-bounty (MIT License) — see
 * IMPROVEMENT_PLAN_3.md §4.
 */
public final class SafetyRules {

    private SafetyRules() {}

    /**
     * Findings that are informational / hardening-only and must NOT appear in
     * confirmed_vulns or suspected_vulns — only in recommendations — UNLESS
     * accompanied by a real exploit chain (see {@link #hasChainEvidence}).
     */
    public static final String NEVER_CONFIRM_PROMPT_TEXT = """
            ## 永不列为漏洞的发现（违反即判定失败）
            以下类型只能出现在 recommendations（加固建议）中，不得进入 confirmed_vulns 或 suspected_vulns：
            1. 仅缺安全响应头（CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy）
            2. 仅缺 Cookie 的 HttpOnly/Secure 标志
            3. CORS 通配符 Access-Control-Allow-Origin: * 且无 Allow-Credentials: true、无凭证数据外带 PoC
            4. 仅 DNS 回连的 SSRF（无内网服务访问、无数据返回）——"生成了 OOB 探针但未证明 HTTP 回连带数据"
            5. 仅有报错回显但无数据读出的 SQLi（错误信息 ≠ 注入成功）
            6. 版本/banner 信息泄露但无对应可利用 CVE 验证
            7. 错误页/响应中出现内网 IP（信息级，除非是 SSRF 链路返回的内网数据）
            8. Self-XSS（只能打自己账号）
            9. 登出 CSRF、非敏感接口的速率限制缺失（搜索框/联系表单）
            10. GraphQL introspection 开启本身（未演示 auth bypass 或 IDOR）
            11. 会话退出后未失效、并发会话（加固项）
            12. 弱 SSL 套件、混合内容（部署配置问题）

            ## Kill signals（出现即降级为 informational 并停止深挖）
            - 反射型 XSS：响应带有效 CSP 且无法绕过；PoC 只有 alert 无 cookie/会话影响路径
            - IDOR：替换 ID 后返回的仍是自己账号的数据（attacker==victim）
            - SQLi：只有报错回显，无任何行数据返回/时间差证据
            - CORS：* 且带凭证请求返回 403、或无 Allow-Credentials
            - 越权："管理员可代用户操作"类——前提是攻击者已是管理员
            - SSRF：只有 DNS ping，无 HTTP 响应体带回内网内容
            """;

    /** Condensed version for Agent's system prompt (tighter token budget — the
     *  full 12-item list would crowd the tool-driven Agent prompt). The
     *  programmatic backstop in VerdictValidator still enforces the full set,
     *  so condensing the prompt text doesn't weaken the rule. Includes the
     *  escalation_path guidance so the Agent marks chainable weak findings. */
    public static final String AGENT_CONDENSED_RULES = """
            ## 误报抑制规则（提交前自检）
            以下只能进加固建议，不得进 confirmed/suspected：缺安全头/Cookie标志、CORS通配符无凭证外带、仅DNS回连的SSRF、
            只有报错回显无数据读出的SQLi、版本/banner泄露、内网IP出现、Self-XSS、登出CSRF/速率限制缺失、GraphQL
            introspection本身、会话未失效、弱SSL。Kill signal出现即降级停止：XSS有CSP且无影响路径、IDOR返回自己数据、
            SQLi仅报错无数据、CORS*且带凭证返回403、越权需攻击者已是管理员、SSRF仅DNS无HTTP内容。
            ## 弱发现的链式升级（escalation_path）
            suspected_vulns 里"有链可走"的弱发现，请在 escalation_path 字段写明升级方向（无链留空）：开放重定向→接OAuth
            redirect_uri窃取授权码；CORS通配符→带凭证外带用户PII；CSRF→敏感操作(改邮箱/转账)；仅DNS的SSRF→内网服务
            访问且数据返回；Host头注入→密码重置邮件用注入host；Self-XSS→CSRF在受害者无感知下触发；GraphQL
            introspection→auth bypass mutation或node(id:)IDOR。
            """;

    /** Full conditionally-valid (chain-escalation) table for Pipeline's
     *  FinalVerdictPrompt — tells the LLM which weak findings become real
     *  vulns when chained, and to record the chain in escalation_path. */
    public static final String CONDITIONALLY_VALID_PROMPT_TEXT = """
            ## 弱发现的链式升级（escalation_path）
            对 suspected_vulns 里"有链可走"的弱发现，在 escalation_path 字段写明升级方向（无链留空）。下表为常见升级路径：
            | 弱发现 | 需要的链 | 成立后等级 |
            | 开放重定向 | + OAuth redirect_uri → 窃取授权码 | 严重 |
            | CORS 通配符 | + 带凭证请求外带用户 PII | 高 |
            | CSRF | + 敏感操作（改邮箱/转账/删账号） | 高 |
            | 仅 DNS 的 SSRF | + 内网服务访问且数据返回 | 中 |
            | Host 头注入 | + 密码重置邮件使用注入的 host | 高 |
            | Self-XSS | + CSRF 在受害者无感知下触发 | 中 |
            | GraphQL introspection | + auth bypass mutation 或 node(id:) IDOR | 高 |
            没有链可走的弱发现 escalation_path 留空，并按上面的 Kill signals 判断是否应降级为 informational。
            """;

    /** Type-name keywords that mark a finding as informational-only (matched
     *  case-insensitively as a substring of the vuln's `type` field). Kept
     *  NARROW on purpose: broad types like bare "信息泄露" are NOT here
     *  (a real sensitive-data exposure legitimately types itself that way),
     *  only specific informational subtypes that are almost never exploitable
     *  on their own. */
    private static final Set<String> INFORMATIONAL_TYPE_KEYWORDS = Set.of(
            "安全头", "security header", "missing header", "缺失安全头", "csp", "hsts",
            "x-frame-options", "x-content-type-options", "referrer-policy",
            "httponly", "secure flag", "cookie标志", "cookie安全",
            "cors通配符", "cors *", "cors配置", "cors misconfig", "access-control-allow-origin",
            "self-xss", "self xss",
            "banner", "版本信息", "版本泄露", "server版本",
            "登出csrf", "logout csrf",
            "速率限制", "rate limit", "rate limiting",
            "graphql introspection", "introspection",
            "会话未失效", "并发会话", "session未失效",
            "ssl", "tls", "弱套件", "mixed content", "混合内容",
            // SSRF/SQLi here are informational VARIANTS only — the kill-signal
            // phrasing ("仅DNS回连"/"仅报错回显") is what marks them info-only.
            // The full SSRF/SQLi findings survive because their evidence will
            // carry chain keywords (内网数据/metadata/行数据/时间差) that the
            // hasChainEvidence exemption checks for.
            "仅dns", "dns回连", "dns ping", "仅报错回显"
    );

    /** Evidence keywords that, if present, exempt an otherwise-informational
     *  finding from demotion — they indicate a real exploit chain rather than
     *  a bare hardening nit. Matched case-insensitively as substrings of the
     *  vuln's `evidence` field. */
    private static final Set<String> CHAIN_EVIDENCE_KEYWORDS = Set.of(
            "凭证", "外带", "credentials", "pii", "个人信息", "敏感字段",
            "跨账号", "跨用户", "他人数据", "attacker", "victim",
            "内网数据", "内网服务", "元数据", "169.254", "metadata", "imds",
            "行数据", "数据读出", "dump", "时间差", "sleep", "pg_sleep", "waitfor delay",
            "auth code", "授权码", "redirect", "重定向链", "开放重定向",
            "密码", "password", "hash", "ssn", "身份证", "token泄露", "密钥泄露"
    );

    /** True if the finding's type matches an informational-only keyword. */
    public static boolean isInformationalType(String type) {
        if (type == null || type.isBlank()) return false;
        String lower = type.toLowerCase();
        for (String kw : INFORMATIONAL_TYPE_KEYWORDS) {
            if (lower.contains(kw)) return true;
        }
        return false;
    }

    /** True if the finding's evidence carries a real-exploit-chain keyword
     *  (exempts it from informational demotion). */
    public static boolean hasChainEvidence(String evidence) {
        if (evidence == null || evidence.isBlank()) return false;
        String lower = evidence.toLowerCase();
        for (String kw : CHAIN_EVIDENCE_KEYWORDS) {
            if (lower.contains(kw)) return true;
        }
        return false;
    }
}
