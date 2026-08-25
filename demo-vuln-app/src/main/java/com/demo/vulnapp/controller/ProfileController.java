package com.demo.vulnapp.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** #9 (wildcard+credentials) / #10 (Origin reflection) in GROUND_TRUTH.md. */
@RestController
public class ProfileController {

    @GetMapping("/api/profile")
    public Object profile(HttpServletResponse response) {
        // BUG: "*" + credentials is a contradictory, vulnerable combination.
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        return Map.of("username", "alice", "email", "alice@example.com");
    }

    @GetMapping("/api/profile2")
    public Object profile2(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("Origin");
        if (origin != null && !origin.isBlank()) {
            // BUG: blindly reflecting the request's Origin header is
            // equivalent to allowing any origin, but still permits credentials.
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
        }
        return Map.of("username", "alice", "email", "alice@example.com");
    }
}
