package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.UserStore;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * #53 VULNERABLE: Shadow API — deprecated v0 endpoints still accessible.
 * These are legacy endpoints from an earlier version that should have been
 * removed but were left behind. They have weaker security controls than
 * the current v1 endpoints (e.g., no authentication required, verbose errors).
 *
 * OWASP API9:2023 — Unrestricted Access to Sensitive Business Flows /
 * Improper Assets Management.
 */
@RestController
@RequestMapping("/api/v0")
public class DeprecatedController {

    private final UserStore userStore;

    public DeprecatedController(UserStore userStore) {
        this.userStore = userStore;
    }

    /**
     * #53: VULNERABLE — legacy user listing with no authentication.
     * The current /api/v1/admin/users requires login; this old version
     * doesn't. Agent should discover this via /api/v0/ path enumeration.
     */
    @GetMapping("/users")
    public List<?> listUsers() {
        return userStore.getAllUsers();
    }

    /**
     * Legacy user detail — returns full entity including sensitive fields.
     * The current version has a /public filtered variant.
     */
    @GetMapping("/users/{id}")
    public Object getUser(@PathVariable int id) {
        var user = userStore.findById(id);
        if (user == null) return Map.of("error", "not found");
        return user;
    }

    /** Legacy debug endpoint — even more information than the v1 version. */
    @GetMapping("/debug")
    public Map<String, Object> debug() {
        return Map.of(
                "version", "v0 (deprecated)",
                "debug", true,
                "internalHost", "10.0.5.23",
                "dbUrl", "jdbc:h2:mem:vulnapp",
                "buildVersion", "0.9.0-SNAPSHOT",
                "uptime", System.currentTimeMillis() / 1000,
                "javaVersion", System.getProperty("java.version"),
                "os", System.getProperty("os.name")
        );
    }
}
