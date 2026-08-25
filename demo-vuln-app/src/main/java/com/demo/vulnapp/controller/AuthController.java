package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.LenientJwtVerifier;
import com.demo.vulnapp.service.StrictJwtVerifier;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** #7 vulnerable (alg:none accepted) / #8 safe (full HS256 verification). */
@RestController
public class AuthController {

    private final LenientJwtVerifier lenientVerifier;
    private final StrictJwtVerifier strictVerifier;

    public AuthController(LenientJwtVerifier lenientVerifier, StrictJwtVerifier strictVerifier) {
        this.lenientVerifier = lenientVerifier;
        this.strictVerifier = strictVerifier;
    }

    @PostMapping("/api/auth/token")
    public Object verifyLenient(@RequestBody Map<String, String> body) {
        var result = lenientVerifier.verify(body.get("token"));
        return Map.of("valid", result.valid(), "reason", result.reason());
    }

    @PostMapping("/api/auth/token-strict")
    public Object verifyStrict(@RequestBody Map<String, String> body) {
        var result = strictVerifier.verify(body.get("token"));
        return Map.of("valid", result.valid(), "reason", result.reason());
    }
}
