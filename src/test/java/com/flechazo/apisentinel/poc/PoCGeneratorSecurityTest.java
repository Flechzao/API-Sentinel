package com.flechazo.apisentinel.poc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PoCGeneratorService P1 安全加固测试
 *
 * 验证 shell / Python / HTML 转义辅助方法，以及生成的 curl / Python 脚本不会因
 * 用户输入（url / cookies / headers / payload / method）含特殊字符而 break out
 * 字符串字面量造成命令/代码注入。
 *
 * @since 1.1.0
 */
class PoCGeneratorSecurityTest {

    private final PoCGeneratorService svc = new PoCGeneratorService(null);

    // ==================== 转义辅助方法 ====================

    @Test
    void escapeSingle_escapesEmbeddedSingleQuote() {
        // POSIX：' -> '\'' （结束引号、转义、重开引号）
        assertEquals("a'\\''b", PoCGeneratorService.escapeSingle("a'b"));
    }

    @Test
    void escapeSingle_nullAndEmpty_returnEmpty() {
        assertEquals("", PoCGeneratorService.escapeSingle(null));
        assertEquals("", PoCGeneratorService.escapeSingle(""));
    }

    @Test
    void escapePy_escapesBackslashAndDoubleQuote() {
        // 单个反斜杠 -> 两个反斜杠
        assertEquals("a\\\\b", PoCGeneratorService.escapePy("a\\b"));
        // 双引号 -> \"
        assertEquals("a\\\"b", PoCGeneratorService.escapePy("a\"b"));
        // 组合：反斜杠 + 双引号，先翻倍反斜杠再转义引号，引号前应跟反斜杠
        String combined = PoCGeneratorService.escapePy("\\\"");
        assertEquals(4, combined.length());  // \,\,\",\" -> 4 chars
        assertTrue(combined.endsWith("\\\""));
        assertTrue(combined.startsWith("\\\\"));
    }

    @Test
    void escapeHtml_escapesAttributeBreakers() {
        String out = PoCGeneratorService.escapeHtml("a\"<b>&c");
        assertFalse(out.contains("\""));  // 双引号被 &quot;
        assertTrue(out.contains("&quot;"));
        assertTrue(out.contains("&lt;"));
        assertTrue(out.contains("&gt;"));
        assertTrue(out.contains("&amp;"));
    }

    @Test
    void singleLine_collapsesNewlines() {
        assertEquals("a b c", PoCGeneratorService.singleLine("a\nb\rc"));
    }

    // ==================== curl 注入防护 ====================

    @Test
    void generate_curlUrlWithSingleQuote_doesNotBreakOut() {
        // url 含单引号：未转义时会闭合 curl 的 '...' 提前注入命令
        String maliciousUrl = "https://x.test/a'$(whoami)'";
        ProofOfConcept poc = svc.generate("SQL Injection", "HIGH", "GET /a", "GET",
                maliciousUrl, "' OR '1'='1", null, null, null, null, null, 80);
        String curl = poc.curlCommand();

        // 关键不变量：单引号被转义为 '\''，证明 escapeSingle 已施加到 url
        assertTrue(curl.contains("'\\''"), "url 中的单引号应被转义为 '\\''");
        // $() 仍在（无害地包在引号内），但不会出现"裸 $() 脱离引号"——
        // 转义后整段 url 仍处在单引号字面量内，shell 不会求值 $()
        assertTrue(curl.contains("$(whoami)"));
    }

    @Test
    void generate_curlCookiesWithSingleQuote_escaped() {
        String cookies = "session=abc';rm -rf /";
        ProofOfConcept poc = svc.generate("XSS", "HIGH", "POST /a", "POST",
                "https://x.test/a", "<svg>", null, null, null, cookies, null, 80);
        String curl = poc.curlCommand();
        // cookies 中的单引号同样被转义，不会闭合 -H 'Cookie: ...'
        assertTrue(curl.contains("Cookie: session=abc'\\'';rm -rf /"));
    }

    @Test
    void generate_curlHeadersWithSingleQuote_escaped() {
        String headers = "X-Custom: val';id";
        ProofOfConcept poc = svc.generate("SSRF", "HIGH", "POST /a", "POST",
                "https://x.test/a", "{}", null, null, null, null, headers, 80);
        String curl = poc.curlCommand();
        assertTrue(curl.contains("X-Custom: val'\\'';id"));
    }

    // ==================== Python 注入防护 ====================

    @Test
    void generate_pythonUrlWithDoubleQuote_doesNotBreakStringLiteral() {
        String maliciousUrl = "https://x\";import os;os.system(\"id\")#";
        ProofOfConcept poc = svc.generate("SQL Injection", "HIGH", "GET /a", "GET",
                maliciousUrl, "x", null, null, null, null, null, 80);
        String python = poc.pythonScript();

        // TARGET = "..." 中双引号被转义为 \"，无法提前闭合字符串
        assertTrue(python.contains("TARGET = \"https://x\\\";import os;os.system(\\\"id\\\")#\""));
    }

    @Test
    void generate_pythonJsonPayloadNotEmittedAsRawCode() {
        // payload 以 { 开头但内含 } ; import os ... 此前会作为裸 Python 代码拼接
        String maliciousPayload = "{\"a\":1};import os;os.system('id')";
        ProofOfConcept poc = svc.generate("SQL Injection", "HIGH", "POST /a", "POST",
                "https://x.test/a", maliciousPayload, null, null, null, null, null, 80);
        String python = poc.pythonScript();

        // 应通过 json.loads("...") 解析转义后的字符串，而非裸拼 data = <payload>
        assertTrue(python.contains("data = json.loads("), "应改用 json.loads 解析，而非裸拼 Python 代码");
        // payload 内的双引号被转义，裸的 import os 不应作为代码出现在 data 赋值行
        assertFalse(python.contains("data = {\"a\":1};import os"));
    }

    @Test
    void generate_pythonCookiesWithDoubleQuote_escaped() {
        String cookies = "k=v\";os.system('id')";
        ProofOfConcept poc = svc.generate("XSS", "HIGH", "POST /a", "POST",
                "https://x.test/a", "x", null, null, null, cookies, null, 80);
        String python = poc.pythonScript();
        // cookie 值的双引号被转义
        assertTrue(python.contains("v\\\""));
    }

    @Test
    void generate_pythonScriptImportsJson() {
        // json.loads 依赖 import json
        ProofOfConcept poc = svc.generate("SQL Injection", "HIGH", "POST /a", "POST",
                "https://x.test/a", "{\"a\":1}", null, null, null, null, null, 80);
        assertTrue(poc.pythonScript().contains("import json"));
    }
}
