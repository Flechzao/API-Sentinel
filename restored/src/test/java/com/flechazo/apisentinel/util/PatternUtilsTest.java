package com.flechazo.apisentinel.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PatternUtilsTest {

    @Test
    void prefixedUuid_isDynamic() {
        // Regression: ns_<uuid>, agent_<uuid> were NOT recognized as dynamic,
        // so /api/namespaces/{id}/agents/{id} never aggregated.
        assertTrue(PatternUtils.isWildcardSegment("ns_fbdf2c73-4070-4eab-9de0-a34402d12467"));
        assertTrue(PatternUtils.isWildcardSegment("agent_60c1c3d5-51bd-4de9-80da-e52a11e39bbd"));
        assertTrue(PatternUtils.isWildcardSegment("tenant-550e8400-e29b-41d4-a716-446655440000"));
    }

    @Test
    void bareUuid_isDynamic() {
        assertTrue(PatternUtils.isWildcardSegment("550e8400-e29b-41d4-a716-446655440000"));
    }

    @Test
    void prefixedNumeric_isDynamic() {
        assertTrue(PatternUtils.isWildcardSegment("user_12345"));
        assertTrue(PatternUtils.isWildcardSegment("order-6789"));
    }

    @Test
    void staticSegments_notDynamic() {
        assertFalse(PatternUtils.isWildcardSegment("namespaces"));
        assertFalse(PatternUtils.isWildcardSegment("agents"));
        assertFalse(PatternUtils.isWildcardSegment("api"));
        assertFalse(PatternUtils.isWildcardSegment("v1"));
        assertFalse(PatternUtils.isWildcardSegment("list"));
    }

    @Test
    void placeholders_and_numeric() {
        assertTrue(PatternUtils.isWildcardSegment("{id}"));
        assertTrue(PatternUtils.isWildcardSegment(":userId"));
        assertTrue(PatternUtils.isWildcardSegment("<id>"));
        assertTrue(PatternUtils.isWildcardSegment("12345"));
        assertTrue(PatternUtils.isWildcardSegment("*"));
    }

    @Test
    void hasPlaceholders_detectsOnlyPlaceholderSyntax() {
        assertTrue(PatternUtils.hasPlaceholders("/api/namespaces/{id}/agents/{id}"));
        assertTrue(PatternUtils.hasPlaceholders("/api/users/:id"));
        assertTrue(PatternUtils.hasPlaceholders("/api/items/<itemId>"));
        // Concrete dynamic values are NOT placeholders
        assertFalse(PatternUtils.hasPlaceholders("/api/namespaces/ns_fbdf2c73-4070-4eab-9de0-a34402d12467/agents/agent_60c1c3d5"));
        assertFalse(PatternUtils.hasPlaceholders("/api/users/12345"));
        assertFalse(PatternUtils.hasPlaceholders("/api/v1/users/list"));
    }
}
