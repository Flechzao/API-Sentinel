package com.flechazo.apisentinel.matching;

import com.flechazo.apisentinel.config.ConfigManager;
import com.flechazo.apisentinel.config.MatchMode;
import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CompositeMatchEngineTest {

    private CompositeMatchEngine engine;
    private ConfigManager configManager;

    @BeforeEach
    void setUp() {
        configManager = new ConfigManager(null);
        TrieMatchEngine trie = new TrieMatchEngine();
        FuzzyMatchEngine fuzzy = new FuzzyMatchEngine();
        engine = new CompositeMatchEngine(trie, fuzzy, configManager);
    }

    @Test
    void fuzzyMode_differentBodies_differentCacheResults() {
        configManager.getConfig().setMatchMode(MatchMode.FUZZY);
        configManager.getConfig().setCheckWholeRequest(true);

        ApiEntry entry1 = new ApiEntry("GET", "/api/users");
        ApiEntry entry2 = new ApiEntry("POST", "/api/orders");
        engine.addEntry(entry1);
        engine.addEntry(entry2);

        // Match with body containing "users"
        List<ApiEntry> r1 = engine.match("/some/path", "redirect=/api/users");
        // Match same URL with body containing "orders"
        List<ApiEntry> r2 = engine.match("/some/path", "redirect=/api/orders");

        // Results must differ — different bodies should NOT share cache
        assertFalse(r1.isEmpty(), "should match /api/users in body");
        assertFalse(r2.isEmpty(), "should match /api/orders in body");
        assertNotEquals(r1.get(0).getApiPath(), r2.get(0).getApiPath());
    }

    @Test
    void fuzzyMode_samebody_usesCachedResult() {
        configManager.getConfig().setMatchMode(MatchMode.FUZZY);
        engine.addEntry(new ApiEntry("GET", "/api/users"));

        List<ApiEntry> r1 = engine.match("/path", "body=/api/users");
        List<ApiEntry> r2 = engine.match("/path", "body=/api/users");

        assertEquals(r1, r2);
    }

    @Test
    void semiExactMode_cacheKeyIgnoresBody() {
        configManager.getConfig().setMatchMode(MatchMode.SEMI_EXACT);
        engine.addEntry(new ApiEntry("GET", "/api/users"));

        List<ApiEntry> r1 = engine.match("/api/users/123", "body1");
        List<ApiEntry> r2 = engine.match("/api/users/123", "body2");

        // Same URL path in SEMI_EXACT mode -> same cache hit regardless of body
        assertEquals(r1, r2);
    }
}
