package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.PasswordHashService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * #37 VULNERABLE: password stored with MD5 (no salt, fast to brute-force).
 * #38 SAFE: password stored with BCrypt (salted, intentionally slow).
 */
@RestController
public class PasswordController {

    private final PasswordHashService hashService;

    public PasswordController(PasswordHashService hashService) {
        this.hashService = hashService;
    }

    @PostMapping("/api/register")
    public Map<String, Object> register(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        if (username.isEmpty() || password.isEmpty()) {
            return Map.of("success", false, "error", "username and password required");
        }
        String hashed = hashService.hash(password);
        return Map.of("success", true,
                "username", username,
                "passwordHash", hashed,
                "algorithm", "hash");
    }

    @PostMapping("/api/signup")
    public Map<String, Object> registerSafe(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        if (username.isEmpty() || password.isEmpty()) {
            return Map.of("success", false, "error", "username and password required");
        }
        String hashed = hashService.hashSecure(password);
        return Map.of("success", true,
                "username", username,
                "passwordHash", hashed,
                "algorithm", "bcrypt");
    }
}
