package com.demo.vulnapp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** #20 in GROUND_TRUTH.md — VULNERABLE: a state-changing POST authenticated
 *  purely by cookie, with no CSRF token check anywhere in the request. */
@RestController
public class CheckoutController {

    private final Map<Integer, AtomicInteger> orderCounts = new ConcurrentHashMap<>();

    @PostMapping("/api/checkout")
    public ResponseEntity<?> checkout(@CookieValue(value = "SESSION_USER", required = false) String sessionUser,
                                       @RequestBody(required = false) Map<String, Object> body) {
        if (sessionUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "not authenticated"));
        }
        int userId;
        try {
            userId = Integer.parseInt(sessionUser);
        } catch (NumberFormatException e) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid session"));
        }
        // BUG: no CSRF token is required or checked — a third-party site can
        // trigger this state change via the victim's browser cookie alone.
        int orderNumber = orderCounts.computeIfAbsent(userId, k -> new AtomicInteger()).incrementAndGet();
        return ResponseEntity.ok(Map.of("status", "order placed", "orderNumber", orderNumber));
    }
}
