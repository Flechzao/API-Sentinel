package com.flechazo.apisentinel.ai.prompt;

/**
 * Prompt for the Intruder AI payload generator. Strict line-per-payload
 * format so the response parses into a payload list without extra scaffolding.
 */
public final class IntruderPayloadPrompt {

    private IntruderPayloadPrompt() {}

    private static final String SYSTEM_PROMPT = """
            你是一名渗透测试载荷生成专家，为 Burp Intruder 生成攻击载荷。
            输出格式要求（必须严格遵守）：
            - 每行一个 payload，不要编号、不要列表符号、不要 markdown 代码块
            - 不要输出任何解释、注释、标题或总结
            - 最多 40 个，按命中可能性从高到低排列
            - payload 是"替换进插入点的值"，不是完整 HTTP 请求
            """;

    public static String getSystemPrompt() {
        return SYSTEM_PROMPT;
    }

    /**
     * Build the generation prompt from the attack's request context.
     *
     * @param oobDomain configured OOB probe domain, or null/blank when OOB is off
     */
    public static String buildUserPrompt(String method, String path, String host,
                                         String paramContext, String baseValue, String oobDomain) {
        StringBuilder sb = new StringBuilder();
        sb.append("## 目标请求\n")
          .append(method).append(" ").append(path).append("\n")
          .append("Host: ").append(host).append("\n\n");

        sb.append("## 插入点\n")
          .append(paramContext).append("\n")
          .append("当前值: ").append(baseValue == null || baseValue.isBlank() ? "(空)" : baseValue)
          .append("\n\n");

        sb.append("""
                ## 生成要求
                根据插入点上下文选择适配的漏洞类别生成 payload：
                - 数字/ID 类值 → SQL 注入（报错探测 + 盲注函数）+ IDOR 相邻 ID
                - URL/IP 值 → SSRF（内网地址、云元数据地址、IP 编码变体）
                - 可能反射的文本 → XSS（事件处理器、编码变体）
                - 文件路径 → 路径穿越（单层/双重编码变体）
                - 命令上下文 → 命令注入（分隔符替换、空白绕过）
                - 凭据字段 → 常见弱口令、认证绕过载荷
                同时包含少量 WAF 绕过变体：大小写混用、注释混淆（/**/）、多层 URL 编码。
                """);

        if (oobDomain != null && !oobDomain.isBlank()) {
            sb.append("OOB 探针域名（SSRF/盲注可用）: ").append(oobDomain).append("\n");
        }

        sb.append("\n现在输出 payload 列表（每行一个，无编号，≤40 个）：");
        return sb.toString();
    }
}
