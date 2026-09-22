package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.RedirectValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Map;

/**
 * #39 VULNERABLE: open redirect — user-supplied URL used directly in Location header.
 * #40 SAFE: URL is validated against a host whitelist before redirecting.
 */
@RestController
public class RedirectController {

    private final RedirectValidator validator;

    public RedirectController(RedirectValidator validator) {
        this.validator = validator;
    }

    @GetMapping("/api/redirect")
    public ResponseEntity<?> redirect(@RequestParam String url) {
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(url))
                .build();
    }

    @GetMapping("/api/goto")
    public ResponseEntity<?> redirectSafe(@RequestParam String url) {
        if (!validator.isAllowed(url)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Redirect target not in whitelist"));
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(url))
                .build();
    }
}
