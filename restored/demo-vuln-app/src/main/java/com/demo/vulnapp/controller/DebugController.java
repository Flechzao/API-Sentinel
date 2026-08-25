package com.demo.vulnapp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** #19 in GROUND_TRUTH.md — VULNERABLE: debug/diagnostic endpoint exposes
 *  internal IPs, connection strings and a "debug: true" flag with no auth. */
@RestController
public class DebugController {

    @GetMapping("/api/debug/config")
    public Map<String, Object> debugConfig() {
        return Map.of(
                "debug", true,
                "internalHost", "10.0.5.23",
                "dbUrl", "jdbc:h2:mem:vulnapp",
                "buildVersion", "1.0.0-SNAPSHOT",
                "featureFlags", Map.of("newCheckout", true));
    }
}
