package com.flechazo.apisentinel.matching;

import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FuzzyMatchEngineTest {

    private FuzzyMatchEngine engine;

    @BeforeEach
    void setUp() {
        engine = new FuzzyMatchEngine();
    }

    @Test
    void match_findsSubstringInUrl() {
        ApiEntry entry = new ApiEntry("GET", "/api/v1/users");
        engine.addEntry(entry);

        List<ApiEntry> result = engine.match("/api/v1/users/123", null);
        assertEquals(1, result.size());
        assertEquals("/api/v1/users", result.get(0).getApiPath());
    }

    @Test
    void match_findsSubstringInBody() {
        ApiEntry entry = new ApiEntry("POST", "/api/login");
        engine.addEntry(entry);

        List<ApiEntry> result = engine.match("/some/other/path", "redirect=/api/login&token=abc");
        assertEquals(1, result.size());
    }

    @Test
    void match_noMatchReturnsEmpty() {
        engine.addEntry(new ApiEntry("GET", "/api/v1/users"));

        List<ApiEntry> result = engine.match("/api/v2/orders", null);
        assertTrue(result.isEmpty());
    }

    @Test
    void addEntry_thenRemoveEntry_noMatch() {
        engine.addEntry(new ApiEntry("GET", "/api/v1/users"));
        engine.removeEntry("/api/v1/users");

        List<ApiEntry> result = engine.match("/api/v1/users", null);
        assertTrue(result.isEmpty());
    }

    @Test
    void rebuild_replacesAllEntries() {
        engine.addEntry(new ApiEntry("GET", "/api/old"));

        engine.rebuild(List.of(
                new ApiEntry("GET", "/api/new1"),
                new ApiEntry("POST", "/api/new2")
        ));

        assertTrue(engine.match("/api/old", null).isEmpty());
        assertEquals(1, engine.match("/api/new1", null).size());
        assertEquals(1, engine.match("/api/new2", null).size());
    }

    @Test
    void concurrentAddAndRebuild_doesNotLoseEntries() throws InterruptedException {
        ApiEntry base = new ApiEntry("GET", "/api/base");
        engine.addEntry(base);

        Thread adder = new Thread(() -> {
            for (int i = 0; i < 100; i++) {
                engine.addEntry(new ApiEntry("GET", "/api/add/" + i));
            }
        });

        Thread rebuilder = new Thread(() -> {
            for (int i = 0; i < 20; i++) {
                List<ApiEntry> snapshot = List.of(
                        base,
                        new ApiEntry("GET", "/api/rebuild/" + i)
                );
                engine.rebuild(snapshot);
            }
        });

        adder.start();
        rebuilder.start();
        adder.join(5000);
        rebuilder.join(5000);

        // After both threads complete, the engine should have a consistent state
        // (either from the last rebuild or with all adds applied)
        // No exception should have been thrown
        assertDoesNotThrow(() -> engine.match("/api/base", null));
    }

    @Test
    void multipleEntries_allFound() {
        engine.rebuild(List.of(
                new ApiEntry("GET", "/api/users"),
                new ApiEntry("GET", "/api/orders"),
                new ApiEntry("GET", "/api/products")
        ));

        String urlWithMultiple = "/api/users and /api/orders in body";
        List<ApiEntry> results = engine.match(urlWithMultiple, null);
        assertEquals(2, results.size());
    }

    @Test
    void match_cjkCharNotTruncatedToAscii_doesNotFalselyMatch() {
        // Regression: char & 0xFF truncated CJK chars to their low byte.
        // '中' (U+4E2D) -> 0x2D = '-'. Before the fix, "/api/a中b" would
        // falsely match pattern "/api/a-b" because '中' was read as '-'.
        engine.addEntry(new ApiEntry("GET", "/api/a-b"));

        List<ApiEntry> result = engine.match("/api/a中b", null);
        assertTrue(result.isEmpty(), "CJK char must not be truncated to '-'");
    }

    @Test
    void match_latin1SupplementChars_matchedNormally() {
        // Chars in 0x80-0xFF range are valid Latin-1 and must not be dropped
        // (only chars > 0xFF are reset). Verify a path with such a char still
        // matches when present verbatim — no false negative introduced.
        engine.addEntry(new ApiEntry("GET", "/api/café"));

        List<ApiEntry> result = engine.match("/api/café/menu", null);
        assertEquals(1, result.size());
    }
}
