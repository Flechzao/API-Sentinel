package com.flechazo.apisentinel.util;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JsonExtractorTest {

    @Test
    void directJsonParsing() {
        String raw = "{\"summary\":\"safe\",\"overall_risk\":\"NONE\",\"findings\":[]}";
        JsonObject result = JsonExtractor.extract(raw);
        assertNotNull(result);
        assertEquals("safe", JsonExtractor.getStr(result, "summary", ""));
        assertEquals("NONE", JsonExtractor.getStr(result, "overall_risk", ""));
    }

    @Test
    void extractFromCodeBlock() {
        String raw = "Here is the analysis:\n```json\n{\"summary\":\"found issue\",\"overall_risk\":\"HIGH\"}\n```\nDone.";
        JsonObject result = JsonExtractor.extract(raw);
        assertNotNull(result);
        assertEquals("HIGH", JsonExtractor.getStr(result, "overall_risk", ""));
    }

    @Test
    void bracketCountingWithNestedJson() {
        String raw = "Some text before {\"outer\":{\"inner\":{\"deep\":\"value\"}},\"key\":\"test\"} and after.";
        JsonObject result = JsonExtractor.extract(raw);
        assertNotNull(result);
        assertEquals("test", JsonExtractor.getStr(result, "key", ""));
        assertTrue(result.has("outer"));
    }

    @Test
    void bracketCountingWithEscapedQuotes() {
        String raw = "prefix {\"msg\":\"he said \\\"hello\\\"\",\"status\":\"ok\"} suffix";
        JsonObject result = JsonExtractor.extract(raw);
        assertNotNull(result);
        assertEquals("ok", JsonExtractor.getStr(result, "status", ""));
    }

    @Test
    void returnsNullForNonJson() {
        assertNull(JsonExtractor.extract("just plain text with no json"));
        assertNull(JsonExtractor.extract(null));
        assertNull(JsonExtractor.extract(""));
    }

    @Test
    void getStrDefaultValue() {
        JsonObject obj = new JsonObject();
        obj.addProperty("exists", "value");
        assertEquals("value", JsonExtractor.getStr(obj, "exists", "default"));
        assertEquals("default", JsonExtractor.getStr(obj, "missing", "default"));
    }

    @Test
    void getDoubleDefaultValue() {
        JsonObject obj = new JsonObject();
        obj.addProperty("score", 0.95);
        assertEquals(0.95, JsonExtractor.getDouble(obj, "score", 0.0), 0.001);
        assertEquals(0.5, JsonExtractor.getDouble(obj, "missing", 0.5), 0.001);
    }

    @Test
    void truncateText() {
        assertEquals("abc...", JsonExtractor.truncate("abcdef", 3));
        assertEquals("ab", JsonExtractor.truncate("ab", 5));
        assertEquals("", JsonExtractor.truncate(null, 5));
    }

    @Test
    void bracketCountingSkipsBrokenFirstCandidate() {
        String raw = "broken { not json } but then {\"valid\":\"data\"} here";
        JsonObject result = JsonExtractor.extract(raw);
        assertNotNull(result);
        assertEquals("data", JsonExtractor.getStr(result, "valid", ""));
    }
}
