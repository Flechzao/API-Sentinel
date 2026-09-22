package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.TokenService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * #33 VULNERABLE: password reset token uses java.util.Random (predictable).
 * #34 SAFE: uses SecureRandom for cryptographically strong token generation.
 */
@RestController
public class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/api/reset-token")
    public Map<String, Object> resetToken(@RequestParam String username) {
        String token = tokenService.generateToken(username);
        return Map.of("success", true,
                "token", token,
                "message", "Password reset link sent to email");
    }

    @PostMapping("/api/password/reset")
    public Map<String, Object> resetTokenSafe(@RequestParam String username) {
        String token = tokenService.generateSecureToken(username);
        return Map.of("success", true,
                "token", token,
                "message", "Password reset link sent to email");
    }
}
