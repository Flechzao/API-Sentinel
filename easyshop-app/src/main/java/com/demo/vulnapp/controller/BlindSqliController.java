package com.demo.vulnapp.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * #29 VULNERABLE: Boolean-based blind SQL injection — no error echo, but response
 * differs based on injected condition (different content length / fields returned).
 * #30 SAFE: same feature via parameterized query.
 */
@RestController
public class BlindSqliController {

    private final JdbcTemplate jdbc;

    public BlindSqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * #29: VULNERABLE — string-concatenated SQL, but errors are swallowed.
     * Response differs: valid product → full details; invalid/empty → just {"found": false}.
     * Agent should detect the behavioral difference between AND 1=1 vs AND 1=2.
     */
    @GetMapping("/api/products/detail")
    public Object productDetail(@RequestParam String id) {
        try {
            String sql = "SELECT id, name, price FROM products WHERE id = " + id;
            List<Map<String, Object>> results = jdbc.queryForList(sql);
            if (results.isEmpty()) {
                return Map.of("found", false);
            }
            return Map.of("found", true, "product", results.get(0));
        } catch (Exception e) {
            // Swallow the error — no stack trace, no DB error message
            return Map.of("found", false);
        }
    }

    /** #30: SAFE — parameterized query, no injection possible. */
    @GetMapping("/api/product-info")
    public Object productDetailSafe(@RequestParam String id) {
        try {
            int numId = Integer.parseInt(id);
            List<Map<String, Object>> results = jdbc.queryForList(
                    "SELECT id, name, price FROM products WHERE id = ?", numId);
            if (results.isEmpty()) {
                return Map.of("found", false);
            }
            return Map.of("found", true, "product", results.get(0));
        } catch (NumberFormatException e) {
            return Map.of("found", false, "error", "Invalid ID format");
        }
    }
}
