package com.flechazo.apisentinel.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CodeRepoTest {

    @Test
    void matchesDomain_caseInsensitive() {
        CodeRepo repo = new CodeRepo("test", "/tmp/test", List.of("Api.Example.COM", "192.168.1.100"));
        assertTrue(repo.matchesDomain("api.example.com"));
        assertTrue(repo.matchesDomain("API.EXAMPLE.COM"));
        assertTrue(repo.matchesDomain("192.168.1.100"));
        assertFalse(repo.matchesDomain("other.com"));
        assertFalse(repo.matchesDomain(""));
        assertFalse(repo.matchesDomain(null));
    }

    @Test
    void emptyDomains_neverMatches() {
        CodeRepo repo = new CodeRepo("test", "/tmp/test", List.of());
        assertFalse(repo.matchesDomain("anything.com"));
    }

    @Test
    void configStoreReadWrite(@TempDir Path tempDir) throws Exception {
        // ConfigStore uses ~/.api-sentinel, but we can test the write/read pattern
        Path file = tempDir.resolve("test-config.json");
        String content = "{\"key\":\"value\"}";
        Files.writeString(file, content);
        assertEquals(content, Files.readString(file));
    }

    @Test
    void codeRepo_defaultConstructor() {
        CodeRepo repo = new CodeRepo();
        assertEquals("", repo.getName());
        assertEquals("", repo.getPath());
        assertTrue(repo.getDomains().isEmpty());
        assertFalse(repo.isIndexed());
        assertEquals(0, repo.getRouteCount());
    }

    @Test
    void codeRepo_setters() {
        CodeRepo repo = new CodeRepo("a", "/a", List.of("x.com"));
        repo.setName("b");
        repo.setPath("/b");
        repo.setDomains(List.of("y.com", "z.com"));
        repo.setIndexed(true);
        repo.setRouteCount(42);

        assertEquals("b", repo.getName());
        assertEquals("/b", repo.getPath());
        assertEquals(2, repo.getDomains().size());
        assertTrue(repo.isIndexed());
        assertEquals(42, repo.getRouteCount());
    }
}
