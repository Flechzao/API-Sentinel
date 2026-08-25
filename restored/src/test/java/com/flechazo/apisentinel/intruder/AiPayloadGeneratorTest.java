package com.flechazo.apisentinel.intruder;

import com.flechazo.apisentinel.ai.provider.LlmProvider;
import com.flechazo.apisentinel.ai.provider.LlmRequest;
import com.flechazo.apisentinel.ai.provider.LlmResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for the Intruder AI payload generator's pure logic. */
class AiPayloadGeneratorTest {

    private static final String RAW = "GET /api/users?id=1001&name=bob HTTP/1.1\r\n"
            + "Host: example.com\r\n"
            + "Cookie: sid=abc\r\n\r\n";

    // ======================== parsePayloadLines ========================

    @Test
    void parsePayloadLines_stripsNumberingAndFences() {
        String content = """
                这是生成的载荷：
                ```
                1. ' OR '1'='1
                2. <img src=x onerror=alert(1)>
                - ../../etc/passwd
                ```
                """;
        List<String> out = AiPayloadGenerator.parsePayloadLines(content);
        assertEquals(3, out.size(), out.toString());
        assertEquals("' OR '1'='1", out.get(0));
        assertEquals("<img src=x onerror=alert(1)>", out.get(1));
        assertEquals("../../etc/passwd", out.get(2));
    }

    @Test
    void parsePayloadLines_dedupAndSkipsProseAndEmpties() {
        String content = "' OR 1=1\n\n' OR 1=1\n注：以上为测试载荷\n说明：仅供测试\n../../etc/passwd\n";
        List<String> out = AiPayloadGenerator.parsePayloadLines(content);
        assertEquals(2, out.size(), out.toString());
        assertEquals("' OR 1=1", out.get(0));
        assertEquals("../../etc/passwd", out.get(1));
    }

    @Test
    void parsePayloadLines_emptyAndNull() {
        assertTrue(AiPayloadGenerator.parsePayloadLines(null).isEmpty());
        assertTrue(AiPayloadGenerator.parsePayloadLines("").isEmpty());
        assertTrue(AiPayloadGenerator.parsePayloadLines("   \n  \n").isEmpty());
    }

    @Test
    void parsePayloadLines_dropsOversizedLines() {
        String big = "A".repeat(3000);
        List<String> out = AiPayloadGenerator.parsePayloadLines("ok\n" + big + "\n");
        assertEquals(1, out.size());
        assertEquals("ok", out.get(0));
    }

    // ======================== extractRequestMeta ========================

    @Test
    void extractRequestMeta_parsesMethodPathHost() {
        String[] meta = AiPayloadGenerator.extractRequestMeta(RAW);
        assertEquals("GET", meta[0]);
        assertEquals("/api/users?id=1001&name=bob", meta[1]);
        assertEquals("example.com", meta[2]);
    }

    @Test
    void extractRequestMeta_emptyFallbacks() {
        String[] meta = AiPayloadGenerator.extractRequestMeta(null);
        assertEquals("GET", meta[0]);
        assertEquals("/", meta[1]);
    }

    // ======================== findParamContext ========================

    @Test
    void findParamContext_queryParam() {
        String ctx = AiPayloadGenerator.findParamContext(RAW, "1001");
        assertTrue(ctx.contains("id"), ctx);
        assertTrue(ctx.contains("查询参数"), ctx);
    }

    @Test
    void findParamContext_cookieHeader() {
        String ctx = AiPayloadGenerator.findParamContext(RAW, "abc");
        assertTrue(ctx.contains("请求头") || ctx.contains("Cookie"), ctx);
    }

    @Test
    void findParamContext_jsonBodyField() {
        String raw = "POST /login HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n"
                + "{\"username\":\"admin\",\"password\":\"secret123\"}";
        String ctx = AiPayloadGenerator.findParamContext(raw, "secret123");
        assertTrue(ctx.contains("password"), ctx);
        assertTrue(ctx.contains("JSON"), ctx);
    }

    @Test
    void findParamContext_absentValue() {
        String ctx = AiPayloadGenerator.findParamContext(RAW, "not-present-value");
        assertTrue(ctx.contains("未知"), ctx);
    }

    // ======================== generator iteration (pure core) ========================

    private static LlmProvider stubProvider(String content) {
        return new LlmProvider() {
            @Override public String getId() { return "stub"; }
            @Override public String getDisplayName() { return "stub"; }
            @Override public CompletableFuture<Boolean> testConnection() {
                return CompletableFuture.completedFuture(true);
            }
            @Override public CompletableFuture<LlmResponse> complete(LlmRequest request) {
                return CompletableFuture.completedFuture(new LlmResponse(
                        content, 10, 10, 100, "stub", LlmResponse.FinishReason.COMPLETE, null));
            }
            @Override public int estimateTokens(String text) { return 0; }
            @Override public boolean isAvailable() { return true; }
            @Override public void configure(String endpoint, String apiKey, String model) {}
        };
    }

    @Test
    void generator_iteratesThenEnds() {
        var gen = new AiPayloadGenerator(null, stubProvider("p-one\np-two\n"), null, null, null);

        assertEquals("p-one", gen.nextPayloadFor("1001", RAW));
        assertEquals("p-two", gen.nextPayloadFor("1001", RAW));
        assertNull(gen.nextPayloadFor("1001", RAW), "third call should signal end");
    }

    @Test
    void generator_cachesPerInsertionPoint_singleLlmCall() {
        int[] calls = {0};
        LlmProvider counting = new LlmProvider() {
            @Override public String getId() { return "stub"; }
            @Override public String getDisplayName() { return "stub"; }
            @Override public CompletableFuture<Boolean> testConnection() {
                return CompletableFuture.completedFuture(true);
            }
            @Override public CompletableFuture<LlmResponse> complete(LlmRequest request) {
                calls[0]++;
                return CompletableFuture.completedFuture(new LlmResponse(
                        "payload-x\n", 10, 10, 100, "stub", LlmResponse.FinishReason.COMPLETE, null));
            }
            @Override public int estimateTokens(String text) { return 0; }
            @Override public boolean isAvailable() { return true; }
            @Override public void configure(String endpoint, String apiKey, String model) {}
        };
        var gen = new AiPayloadGenerator(null, counting, null, null, null);
        gen.nextPayloadFor("1001", RAW); // triggers generation
        gen.nextPayloadFor("1001", RAW); // cached
        gen.nextPayloadFor("1001", RAW); // end
        gen.nextPayloadFor("1001", RAW); // still end
        assertEquals(1, calls[0], "LLM should be called exactly once per insertion point");
    }

    @Test
    void generator_distinctInsertionPoints_independentCaches() {
        var gen = new AiPayloadGenerator(null, stubProvider("px\npy\n"), null, null, null);
        assertEquals("px", gen.nextPayloadFor("1001", RAW));
        // Different base value → separate cache entry, starts from the beginning.
        assertEquals("px", gen.nextPayloadFor("2002", RAW));
    }

    @Test
    void generator_noProvider_ends() {
        // null factory + null direct provider → no payloads, end immediately.
        var gen = new AiPayloadGenerator(null, null, null, null, null);
        assertNull(gen.nextPayloadFor("1001", RAW), "no configured provider should yield end");
    }
}
