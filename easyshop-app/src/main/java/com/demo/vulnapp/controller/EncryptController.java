package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.CryptoService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * #35 VULNERABLE: encryption key is hardcoded in the service class.
 * #36 SAFE: encryption key is read from environment variable.
 */
@RestController
public class EncryptController {

    private final CryptoService cryptoService;

    public EncryptController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @PostMapping("/api/encrypt")
    public Map<String, Object> encrypt(@RequestBody Map<String, String> body) {
        String data = body.getOrDefault("data", "");
        try {
            String ciphertext = cryptoService.encrypt(data);
            return Map.of("success", true, "ciphertext", ciphertext);
        } catch (Exception e) {
            return Map.of("success", false, "error", e.getMessage());
        }
    }

    @PostMapping("/api/seal")
    public Map<String, Object> encryptSafe(@RequestBody Map<String, String> body) {
        String data = body.getOrDefault("data", "");
        try {
            String ciphertext = cryptoService.encryptSecure(data);
            return Map.of("success", true, "ciphertext", ciphertext);
        } catch (Exception e) {
            return Map.of("success", false, "error", e.getMessage());
        }
    }
}
