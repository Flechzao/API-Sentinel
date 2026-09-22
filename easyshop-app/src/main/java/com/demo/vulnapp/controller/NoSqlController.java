package com.demo.vulnapp.controller;

import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * #47 VULNERABLE: NoSQL injection — JSON query operators ($ne, $gt, $regex) are
 * evaluated directly against in-memory data without sanitization.
 * #48 SAFE: strips any keys starting with '$' before evaluating the query.
 *
 * Simulates a MongoDB-like query API over in-memory user records.
 * The "login" endpoint is the key demo: sending {"username": {"$ne": ""}, "password": {"$ne": ""}}
 * bypasses authentication by matching the first user whose fields are "not equal to empty".
 */
@RestController
public class NoSqlController {

    private static final List<Map<String, Object>> USERS = List.of(
            Map.of("id", 1, "username", "alice", "password", "alice123", "role", "user", "email", "alice@example.com"),
            Map.of("id", 2, "username", "bob", "password", "bob456", "role", "user", "email", "bob@example.com"),
            Map.of("id", 3, "username", "admin", "password", "admin789", "role", "admin", "email", "admin@example.com")
    );

    /**
     * #47: VULNERABLE — evaluates $ne, $gt, $regex operators from user-supplied JSON.
     * POST body: {"username": {"$ne": ""}, "password": {"$ne": ""}} → returns all users (auth bypass).
     */
    @PostMapping("/api/mongo/login")
    public Map<String, Object> login(@RequestBody Map<String, Object> query) {
        List<Map<String, Object>> matched = USERS.stream()
                .filter(user -> matchesQuery(user, query))
                .collect(Collectors.toList());
        if (matched.isEmpty()) {
            return Map.of("success", false, "error", "invalid credentials");
        }
        // Return first match (simulates "find one")
        Map<String, Object> user = new LinkedHashMap<>(matched.get(0));
        user.put("success", true);
        user.put("message", "login successful");
        return user;
    }

    /**
     * #48: SAFE — strips operator keys (starting with '$') before matching.
     * Only exact string equality is checked.
     */
    @PostMapping("/api/mongo/auth")
    public Map<String, Object> loginSafe(@RequestBody Map<String, Object> query) {
        // Sanitize: reject any query value that is a Map (operator object)
        for (Map.Entry<String, Object> entry : query.entrySet()) {
            if (entry.getValue() instanceof Map) {
                return Map.of("success", false, "error", "query operators not allowed");
            }
        }
        List<Map<String, Object>> matched = USERS.stream()
                .filter(user -> matchesExact(user, query))
                .collect(Collectors.toList());
        if (matched.isEmpty()) {
            return Map.of("success", false, "error", "invalid credentials");
        }
        Map<String, Object> user = new LinkedHashMap<>(matched.get(0));
        user.put("success", true);
        user.put("message", "login successful");
        return user;
    }

    /** Evaluate a MongoDB-style query with operator support (vulnerable). */
    @SuppressWarnings("unchecked")
    private boolean matchesQuery(Map<String, Object> doc, Map<String, Object> query) {
        for (Map.Entry<String, Object> entry : query.entrySet()) {
            String field = entry.getKey();
            Object condition = entry.getValue();
            Object docValue = doc.get(field);

            if (condition instanceof Map) {
                Map<String, Object> ops = (Map<String, Object>) condition;
                for (Map.Entry<String, Object> op : ops.entrySet()) {
                    if (!evalOperator(docValue, op.getKey(), op.getValue())) {
                        return false;
                    }
                }
            } else {
                // Exact match
                if (!Objects.equals(docValue, condition)) return false;
            }
        }
        return true;
    }

    private boolean evalOperator(Object docValue, String op, Object operand) {
        return switch (op) {
            case "$eq" -> Objects.equals(docValue, operand);
            case "$ne" -> !Objects.equals(docValue, operand);
            case "$gt" -> docValue instanceof Comparable && operand instanceof Comparable
                    && ((Comparable) docValue).compareTo(operand) > 0;
            case "$gte" -> docValue instanceof Comparable && operand instanceof Comparable
                    && ((Comparable) docValue).compareTo(operand) >= 0;
            case "$lt" -> docValue instanceof Comparable && operand instanceof Comparable
                    && ((Comparable) docValue).compareTo(operand) < 0;
            case "$lte" -> docValue instanceof Comparable && operand instanceof Comparable
                    && ((Comparable) docValue).compareTo(operand) <= 0;
            case "$regex" -> docValue != null && docValue.toString().matches(operand.toString());
            case "$in" -> operand instanceof List && ((List<?>) operand).contains(docValue);
            default -> false;
        };
    }

    /** Only exact string equality matching (safe). */
    private boolean matchesExact(Map<String, Object> doc, Map<String, Object> query) {
        for (Map.Entry<String, Object> entry : query.entrySet()) {
            if (!Objects.equals(doc.get(entry.getKey()), entry.getValue())) return false;
        }
        return true;
    }
}
