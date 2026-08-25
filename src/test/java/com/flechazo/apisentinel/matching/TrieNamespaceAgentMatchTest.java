package com.flechazo.apisentinel.matching;

import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TrieNamespaceAgentMatchTest {

    @Test
    void placeholderPattern_matchesConcreteUuidPath() {
        TrieMatchEngine trie = new TrieMatchEngine();
        ApiEntry pattern = new ApiEntry("GET", "/api/namespaces/{id}/agents/{id}");
        trie.addEntry(pattern);

        String concrete = "/api/namespaces/ns_fbdf2c73-4070-4eab-9de0-a34402d12467/agents/agent_60c1c3d5-51bd-4de9-80da-e52a11e39bbd";
        List<ApiEntry> matches = trie.matchExact(concrete);
        assertFalse(matches.isEmpty(), "concrete UUID path should match the {id} pattern");
        assertEquals("/api/namespaces/{id}/agents/{id}", matches.get(0).getApiPath());
    }

    @Test
    void placeholderPattern_matchesNumericPath() {
        TrieMatchEngine trie = new TrieMatchEngine();
        trie.addEntry(new ApiEntry("GET", "/api/namespaces/{id}/agents/{id}"));
        List<ApiEntry> matches = trie.matchExact("/api/namespaces/42/agents/7");
        assertFalse(matches.isEmpty());
    }

    @Test
    void differentSegmentCount_doesNotMatch() {
        TrieMatchEngine trie = new TrieMatchEngine();
        trie.addEntry(new ApiEntry("GET", "/api/namespaces/{id}/agents/{id}"));
        // 6 segments vs 5 — should not match
        List<ApiEntry> matches = trie.matchExact("/api/namespaces/42/agents/7/extra");
        // matches nothing (no glob-star); may be empty or glob — here expect empty
        assertTrue(matches.isEmpty());
    }

    @Test
    void sixSegmentPattern_matchesConcreteSubResource() {
        // The user's exact case: /api/namespaces/{id}/agents/{id}/feedback-messages
        TrieMatchEngine trie = new TrieMatchEngine();
        trie.addEntry(new ApiEntry("GET", "/api/namespaces/{id}/agents/{id}/feedback-messages"));
        List<ApiEntry> matches = trie.matchExact(
                "/api/namespaces/ns_fbdf2c73-4070-4eab-9de0-a34402d12467/agents/agent_60c1c3d5-51bd-4de9-80da-e52a11e39bbd/feedback-messages");
        assertFalse(matches.isEmpty(), "6-seg concrete should match 6-seg {id} pattern");
    }

    @Test
    void multiplePatterns_shareWildcardWithoutConflict() {
        TrieMatchEngine trie = new TrieMatchEngine();
        trie.addEntry(new ApiEntry("GET", "/api/namespaces/{id}/agents/{id}/feedback-messages"));
        trie.addEntry(new ApiEntry("GET", "/api/namespaces/{id}/agents/{id}/knowledge"));
        assertEquals(1, trie.matchExact("/api/namespaces/ns_abc/agents/agent_xyz/feedback-messages").size());
        assertEquals(1, trie.matchExact("/api/namespaces/ns_abc/agents/agent_xyz/knowledge").size());
    }
}
