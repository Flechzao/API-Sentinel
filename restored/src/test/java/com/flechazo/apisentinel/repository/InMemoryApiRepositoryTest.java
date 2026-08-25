package com.flechazo.apisentinel.repository;

import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryApiRepositoryTest {

    @Test
    void knownDomains_reflectsAddedEntries() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        repo.add(entry("GET", "/api/a", "api.example.com"));
        repo.add(entry("POST", "/api/b", "shop.example.com"));

        // getKnownDomains() normalizes to lowercase; callers (e.g. focus filter)
        // lowercase their host before checking.
        assertTrue(repo.getKnownDomains().contains("api.example.com"));
        assertTrue(repo.getKnownDomains().contains("shop.example.com"));
    }

    @Test
    void findByDomain_isCaseInsensitive() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        repo.add(entry("GET", "/api/a", "api.example.com"));
        // Mixed-case lookup must still match the lowercased bucket
        assertFalse(repo.findByDomain("API.Example.COM").isEmpty());
    }

    @Test
    void findByDomain_returnsOnlyMatchingEntries() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        repo.add(entry("GET", "/api/a", "api.example.com"));
        repo.add(entry("GET", "/api/b", "shop.example.com"));
        repo.add(entry("GET", "/api/c", "api.example.com"));

        List<ApiEntry> api = repo.findByDomain("api.example.com");
        assertEquals(2, api.size());
        List<ApiEntry> shop = repo.findByDomain("shop.example.com");
        assertEquals(1, shop.size());
        assertTrue(repo.findByDomain("unknown.com").isEmpty());
    }

    @Test
    void remove_updatesDomainIndex() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        repo.add(entry("GET", "/api/a", "api.example.com"));
        repo.remove("/api/a");

        assertFalse(repo.getKnownDomains().contains("api.example.com"));
        assertTrue(repo.findByDomain("api.example.com").isEmpty());
    }

    @Test
    void updateDomain_movesEntryBetweenBuckets() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        repo.add(entry("GET", "/api/a", "old.example.com"));

        repo.updateDomain("/api/a", "new.example.com");

        assertFalse(repo.getKnownDomains().contains("old.example.com"));
        assertTrue(repo.getKnownDomains().contains("new.example.com"));
        assertEquals(1, repo.findByDomain("new.example.com").size());
    }

    @Test
    void clear_resetsDomainIndex() {
        InMemoryApiRepository repo = new InMemoryApiRepository();
        repo.add(entry("GET", "/api/a", "api.example.com"));
        repo.clear();
        assertTrue(repo.getKnownDomains().isEmpty());
    }

    private static ApiEntry entry(String method, String path, String domain) {
        ApiEntry e = new ApiEntry(method, path);
        e.setDomain(domain);
        return e;
    }
}
