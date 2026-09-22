package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PageLocator}.
 * Tests Level 3 (RESTful path inference) which doesn't require a real browser.
 */
class PageLocatorTest {

    private PageLocator locator;

    @BeforeEach
    void setUp() {
        locator = new PageLocator(new LeveledLogger(null));
    }

    // ========== Level 3: RESTful Path Inference ==========

    @Test
    void inferFromApiPath_simpleResource() {
        var candidates = locator.inferFromApiPath("/api/v1/orders", "http://localhost:3000");

        assertThat(candidates).isNotEmpty();
        // Should include /orders as a primary candidate
        assertThat(candidates.stream().anyMatch(c ->
                c.url().contains("/orders"))).isTrue();
    }

    @Test
    void inferFromApiPath_withSubResource() {
        var candidates = locator.inferFromApiPath("/api/v1/users/123/roles", "http://localhost:3000");

        assertThat(candidates).isNotEmpty();
        // Should include /users as primary resource
        assertThat(candidates.stream().anyMatch(c ->
                c.url().contains("/users"))).isTrue();
    }

    @Test
    void inferFromApiPath_withBaseUrl() {
        var candidates = locator.inferFromApiPath("/api/v1/products", "http://frontend.example.com");

        assertThat(candidates).isNotEmpty();
        // All candidates should start with the base URL
        assertThat(candidates).allMatch(c ->
                c.url().startsWith("http://frontend.example.com"));
    }

    @Test
    void inferFromApiPath_emptyBaseUrl() {
        var candidates = locator.inferFromApiPath("/api/v1/items", "");

        assertThat(candidates).isNotEmpty();
        // Should still produce candidates without base URL
        assertThat(candidates.stream().anyMatch(c ->
                c.url().contains("/items"))).isTrue();
    }

    @Test
    void inferFromApiPath_nullPath() {
        var candidates = locator.inferFromApiPath(null, "http://localhost:3000");
        assertThat(candidates).isEmpty();
    }

    @Test
    void inferFromApiPath_emptyPath() {
        var candidates = locator.inferFromApiPath("", "http://localhost:3000");
        assertThat(candidates).isEmpty();
    }

    @Test
    void inferFromApiPath_confidenceIsMedium() {
        var candidates = locator.inferFromApiPath("/api/v1/orders", "http://localhost:3000");

        assertThat(candidates).allMatch(c -> "medium".equals(c.confidence()));
    }

    @Test
    void inferFromApiPath_includesAdminVariant() {
        var candidates = locator.inferFromApiPath("/api/v1/users", "http://localhost:3000");

        // Should include /admin/users variant
        assertThat(candidates.stream().anyMatch(c ->
                c.url().contains("/admin/users"))).isTrue();
    }

    @Test
    void inferFromApiPath_includesNewSuffix() {
        var candidates = locator.inferFromApiPath("/api/v1/orders", "http://localhost:3000");

        // Should include /orders/new variant (for POST operations)
        assertThat(candidates.stream().anyMatch(c ->
                c.url().contains("/orders/new"))).isTrue();
    }

    // ========== Level 2: Crawl Mapping (without browser) ==========

    @Test
    void buildApiPageMapping_legacyOverload_skipsParameterizedRoutes() {
        var routes = List.of("/users", "/users/:id", "/products", "/orders/{id}");
        var mapping = locator.buildApiPageMapping("http://localhost:3000", routes, 10);

        // Parameterized routes should be skipped
        assertThat(mapping).doesNotContainKey("/users/:id");
        assertThat(mapping).doesNotContainKey("/orders/{id}");
        // Non-parameterized routes should be present
        assertThat(mapping).containsKey("/users");
        assertThat(mapping).containsKey("/products");
    }

    @Test
    void buildApiPageMapping_legacyOverload_emptyInputs() {
        assertThat(locator.buildApiPageMapping(null, List.of(), 10)).isEmpty();
        assertThat(locator.buildApiPageMapping("", List.of("/users"), 10)).isEmpty();
        assertThat(locator.buildApiPageMapping("http://localhost", List.of(), 10)).isEmpty();
    }

    @Test
    void buildApiPageMapping_legacyOverload_respectsMaxPages() {
        var routes = List.of("/a", "/b", "/c", "/d", "/e");
        var mapping = locator.buildApiPageMapping("http://localhost:3000", routes, 3);

        // Should visit at most 3 pages
        int totalVisited = mapping.values().stream().mapToInt(s -> s.size()).sum();
        assertThat(totalVisited).isLessThanOrEqualTo(3);
    }

    // ========== CandidatePage record ==========

    @Test
    void candidatePage_recordAccessors() {
        var candidate = new PageLocator.CandidatePage(
                "http://localhost:3000/orders", "high", "JS bundle match");

        assertThat(candidate.url()).isEqualTo("http://localhost:3000/orders");
        assertThat(candidate.confidence()).isEqualTo("high");
        assertThat(candidate.reason()).isEqualTo("JS bundle match");
    }
}
