package com.demo.vulnapp.controller;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** #1 vulnerable / #2 safe in GROUND_TRUTH.md — same feature, string
 *  concatenation vs. a parameterized query. */
@RestController
public class SqliController {

    private final JdbcTemplate jdbc;

    public SqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** #1: VULNERABLE — string-concatenated SQL, raw DB error echoed back. */
    @GetMapping("/api/users/search")
    public Object search(@RequestParam String name) {
        try {
            String sql = "SELECT id, username, email FROM users WHERE username LIKE '%" + name + "%'";
            return jdbc.queryForList(sql);
        } catch (DataAccessException e) {
            Throwable cause = e.getMostSpecificCause();
            return Map.of("error", cause != null ? cause.getMessage() : e.getMessage());
        }
    }

    /** #2: SAFE — same feature via a parameterized query. */
    @GetMapping("/api/products/search")
    public List<Map<String, Object>> searchProducts(@RequestParam String name) {
        return jdbc.queryForList("SELECT id, name, price FROM products WHERE name LIKE ?", "%" + name + "%");
    }
}
