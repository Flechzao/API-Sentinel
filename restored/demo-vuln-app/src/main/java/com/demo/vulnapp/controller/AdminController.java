package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.UserStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * #6 in GROUND_TRUTH.md — VULNERABLE: only checks that the caller is
 * authenticated (has *any* session cookie), never checks whether that user
 * actually has the admin role. The real role check lives in AdminGuard,
 * which this controller never calls — see AdminGuard's javadoc.
 */
@RestController
public class AdminController {

    private final UserStore userStore;

    public AdminController(UserStore userStore) {
        this.userStore = userStore;
    }

    @GetMapping("/api/admin/users")
    public ResponseEntity<?> listUsers(@CookieValue(value = "SESSION_USER", required = false) String sessionUser) {
        if (sessionUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "not authenticated"));
        }
        // BUG: any authenticated user reaches this point — no role check.
        return ResponseEntity.ok(List.of(
                userStore.findById(1), userStore.findById(2), userStore.findById(3)));
    }
}
