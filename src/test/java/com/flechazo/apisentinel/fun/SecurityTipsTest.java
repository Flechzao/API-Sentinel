package com.flechazo.apisentinel.fun;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SecurityTipsTest {

    @Test
    void sqlInjectionReturnsTip() {
        String tip = SecurityTips.getTip("SQL注入");
        assertNotNull(tip);
        assertTrue(tip.length() > 10);
    }

    @Test
    void xssReturnsTip() {
        String tip = SecurityTips.getTip("反射型 XSS");
        assertNotNull(tip);
    }

    @Test
    void idorReturnsTip() {
        String tip = SecurityTips.getTip("越权访问/IDOR");
        assertNotNull(tip);
    }

    @Test
    void ssrfReturnsTip() {
        String tip = SecurityTips.getTip("SSRF");
        assertNotNull(tip);
    }

    @Test
    void pathTraversalReturnsTip() {
        String tip = SecurityTips.getTip("路径穿越");
        assertNotNull(tip);
    }

    @Test
    void sstiReturnsTip() {
        String tip = SecurityTips.getTip("SSTI");
        assertNotNull(tip);
    }

    @Test
    void xxeReturnsTip() {
        String tip = SecurityTips.getTip("XXE");
        assertNotNull(tip);
    }

    @Test
    void commandInjectionReturnsTip() {
        String tip = SecurityTips.getTip("命令注入");
        assertNotNull(tip);
    }

    @Test
    void authBypassReturnsTip() {
        String tip = SecurityTips.getTip("认证绕过");
        assertNotNull(tip);
    }

    @Test
    void corsReturnsTip() {
        String tip = SecurityTips.getTip("CORS");
        assertNotNull(tip);
    }

    @Test
    void businessLogicReturnsTip() {
        String tip = SecurityTips.getTip("业务逻辑");
        assertNotNull(tip);
    }

    @Test
    void infoDisclosureReturnsTip() {
        String tip = SecurityTips.getTip("信息泄露");
        assertNotNull(tip);
    }

    @Test
    void unknownTypeReturnsNull() {
        assertNull(SecurityTips.getTip("完全未知类型XYZ"));
    }

    @Test
    void nullTypeReturnsNull() {
        assertNull(SecurityTips.getTip(null));
    }

    @Test
    void emptyTypeReturnsNull() {
        assertNull(SecurityTips.getTip(""));
    }

    @Test
    void randomTipNeverNull() {
        for (int i = 0; i < 20; i++) {
            assertNotNull(SecurityTips.getRandomTip());
        }
    }

    @Test
    void randomTipVaries() {
        // Run 20 times, should get at least 2 different tips
        java.util.Set<String> tips = new java.util.HashSet<>();
        for (int i = 0; i < 20; i++) {
            tips.add(SecurityTips.getRandomTip());
        }
        assertTrue(tips.size() >= 2, "Random tips should vary");
    }

    @Test
    void tipForSqlContainsRelevantKeyword() {
        String tip = SecurityTips.getTip("SQL注入");
        assertTrue(tip.contains("SQL") || tip.contains("参数化") || tip.contains("注入")
                || tip.contains("查询") || tip.contains("盲注") || tip.contains("OWASP"),
                "SQL tip should contain relevant keywords: " + tip);
    }

    @Test
    void tipForXssContainsRelevantKeyword() {
        String tip = SecurityTips.getTip("XSS");
        assertTrue(tip.contains("XSS") || tip.contains("脚本") || tip.contains("编码")
                || tip.contains("CSP") || tip.contains("DOM") || tip.contains("OWASP"),
                "XSS tip should contain relevant keywords: " + tip);
    }

    @Test
    void tipForIdorContainsRelevantKeyword() {
        String tip = SecurityTips.getTip("IDOR");
        assertTrue(tip.contains("IDOR") || tip.contains("授权") || tip.contains("归属")
                || tip.contains("OWASP") || tip.contains("越权"),
                "IDOR tip should contain relevant keywords: " + tip);
    }
}
